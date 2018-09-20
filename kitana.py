#!/usr/bin/python3

import os
import platform
import traceback
from collections import OrderedDict

import cherrypy
import requests
import xmltodict
import glob
import json
import uuid

from jinja2 import Environment, PackageLoader, select_autoescape, contextfunction
from urllib.parse import urlparse

from requests import HTTPError, Timeout

from plugins.SassCompilerPlugin import SassCompilerPlugin
from tools.urls import BaseUrlOverride

env = Environment(
    loader=PackageLoader('kitana', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

template = env.get_template('index.jinja2')


class Kitana(object):
    PRODUCT_IDENTIFIER = "Kitana"
    VERSION = "0.0.1"
    CLIENT_IDENTIFIER_BASE = "{}_{}".format(PRODUCT_IDENTIFIER, VERSION)
    initialized = False
    timeout = 5
    plextv_timeout = 15

    def __init__(self, prefix="/"):
        self.initialized = False
        self.prefix = prefix
        self.plex_token = None
        self.username = None
        self.server_name = None
        self.server_addr = None
        self.session = requests.Session()
        self.req_defaults = {"timeout": self.timeout}
        self.initialized = True

    def template_url(self, url):
        if url.startswith("/:") or url.startswith("/library"):
            url = self.server_addr + url[1:]
            if urlparse(url).query:
                url += '&'
            else:
                url += '?'
            url += "X-Plex-Token={}".format(self.plex_token)
            return url

        if not url.startswith(self.prefix):
            return self.prefix + url
        return url

    def plex_dispatch(self, path="video/subzero"):
        headers = {
            "X-Plex-Token": self.plex_token
        }
        r = self.session.get(self.server_addr + path, headers=headers, **self.req_defaults)
        r.raise_for_status()
        content = xmltodict.parse(r.content, attr_prefix="")
        # print(json.dumps(content["MediaContainer"]))
        return template.render(data=content["MediaContainer"], **self.default_context)

    @property
    def default_context(self):
        return {
            "logged_in": bool(cherrypy.session.get("plex_token")),
            "username": cherrypy.session.get("username"),
            "server_name": cherrypy.session.get("server_name"),
        }

    @property
    def client_identifier(self):
        ci = cherrypy.session.get("client_identifier")
        if not ci:
            cherrypy.session["client_identifier"] = ci = str(uuid.uuid4())
        return ci

    @property
    def plex_token(self):
        token = cherrypy.session.get("plex_token")
        if not token:
            print("No token, redirecting")
            raise cherrypy.HTTPRedirect("/token")
        return token

    @plex_token.setter
    def plex_token(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["plex_token"] = value

    @property
    def username(self):
        return cherrypy.session.get("username")

    @username.setter
    def username(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["username"] = value

    @property
    def server_name(self):
        return cherrypy.session.get("server_name")

    @server_name.setter
    def server_name(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["server_name"] = value

    @property
    def server_addr(self):
        return cherrypy.session.get("server_addr")

    @server_addr.setter
    def server_addr(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["server_addr"] = value + "/" if value else None

    @property
    def plex_headers(self):
        return {
            "X-Plex-Client-Identifier": self.client_identifier,
            "X-Plex-Product": self.PRODUCT_IDENTIFIER,
            "X-Plex-Provides": "controller",
            "X-Plex-Version": self.VERSION,
            "X-Plex-Platform": platform.system(),
            "X-Plex-Device": "{} {}".format(platform.system(), platform.release()),
            "X-Plex-Device-Name": platform.node(),
            "X-Plex-Platform-Version": platform.release(),
            'Accept': 'application/json',
        }

    @property
    def full_headers(self):
        return dict(self.plex_headers, **{
            "X-Plex-Token": self.plex_token
        })

    def fill_user_info(self):
        # get user info
        r = self.session.get("https://plex.tv/users/account", headers=self.full_headers, timeout=self.plextv_timeout)
        r.raise_for_status()
        content = xmltodict.parse(r.content, attr_prefix="")
        self.username = content["user"]["username"][0]

    def ensure_pms_data(self):
        if not self.username:
            self.fill_user_info()

        if not self.server_name or not self.server_addr:
            qs = {}
            if self.server_name:
                qs["server_name"] = self.server_name
            if self.server_addr:
                qs["server_addr"] = self.server_addr

            raise cherrypy.HTTPRedirect(
                cherrypy.url("/servers", qs=qs))

    def connect_pms(self, server_name=None, server_addr=None, blacklist_addr=None):
        r = self.session.get("https://plex.tv/api/resources?includeHttps=1&includeRelay=1", headers=self.full_headers,
                             timeout=self.plextv_timeout)
        r.raise_for_status()
        content = xmltodict.parse(r.content, attr_prefix="")
        servers = OrderedDict()
        # import pprint
        # pprint.pprint(content)
        if not server_addr:
            for device in content["MediaContainer"].get("Device", []):
                if device["provides"] != "server" or not bool(device["presence"]):
                    continue

                public_address_matches = device["publicAddressMatches"] == "1"
                https_required = device["httpsRequired"] == "1"

                for connection in device["Connection"]:
                    if not public_address_matches and connection["local"] == "1":
                        continue

                    elif https_required and connection["protocol"] != "https":
                        continue

                    if device["name"] not in servers:
                        servers[device["name"]] = {"connections": [], "owned": device["owned"] == "1"}

                    if blacklist_addr and connection["uri"] in blacklist_addr:
                        print("{}: {} on blacklist, skipping".format(device["name"], connection["uri"]))
                        continue

                    servers[device["name"]]["connections"].append(connection)
                    if server_name and server_name == device["name"]:
                        server_addr = connection["uri"]
                        break

        if server_name and server_addr:
            self.server_name = server_name
            self.server_addr = server_addr

            print("Server set to: {}, {}".format(server_name, server_addr))
            print("Verifying {}: {}".format(server_name, server_addr))
            try:
                self.session.get(self.server_addr + "servers", headers=self.full_headers, **self.req_defaults)
            except HTTPError as e:
                if e.response.status_code == 401:
                    self.plex_token = None
                    self.server_name = None
                    self.server_addr = None
                    print("Access denied when accessing {}, going to login".format(self.server_name))
                    raise cherrypy.HTTPRedirect("/token")
            except Exception as e:
                if not blacklist_addr:
                    blacklist_addr = []
                blacklist_addr.append(server_addr)
                print("{}: Blacklisting {} due to: {!r}".format(server_name, server_addr, e))
                return self.connect_pms(server_name=server_name, server_addr=None, blacklist_addr=blacklist_addr)

            raise cherrypy.HTTPRedirect("/")

        return servers

    @cherrypy.expose
    def servers(self, server_name=None, server_addr=None):
        servers = self.connect_pms(server_name=server_name, server_addr=server_addr)
        template = env.get_template('servers.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context, servers=servers)

    @cherrypy.expose("token")
    def get_plex_token(self, username=None, password=None, token=None):
        if username and password:
            r = self.session.post("https://plex.tv/users/sign_in.json", {
                "user[login]": username,
                "user[password]": password,
            }, headers=self.plex_headers, **self.req_defaults)
            r.raise_for_status()
            self.plex_token = r.json()["user"]["authToken"]
            raise cherrypy.HTTPRedirect("/")

        if token:
            self.plex_token = token
            return json.dumps({"url": cherrypy.url(self.prefix)})

        template = env.get_template('token.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context)

    @cherrypy.expose
    def logout(self):
        self.plex_token = None
        self.server_name = None
        self.server_addr = None
        raise cherrypy.HTTPRedirect("/")

    @cherrypy.expose
    def default(self, *args, **kwargs):
        self.ensure_pms_data()

        query_params = "&".join("=".join([k, v]) for k, v in kwargs.items())
        path = "/".join(args) + ("?" + query_params if query_params else "")
        # print(args, path)
        kw = {}
        if path:
            kw["path"] = path

        try:
            return self.plex_dispatch(**kw)
        except (HTTPError, Timeout) as e:
            if isinstance(e, HTTPError):
                if e.response.status_code == 401:
                    print("Access denied when accessing {}, going to server selection".format(self.server_name))
                    self.server_name = None
                    self.server_addr = None
                    raise cherrypy.HTTPRedirect("/servers")
                elif e.response.status_code == 404:
                    print("YEEE")
                    raise cherrypy.HTTPRedirect("/plugins")

            print("Error when connecting to '{}', trying other connection to: {}".format(self.server_addr,
                                                                                         self.server_name))
            return self.connect_pms(self.server_name)


if __name__ == "__main__":
    baseDir = os.path.dirname(os.path.abspath(__file__))

    prefix = "/"

    cherrypy.config.update(
        {
            'server.socket_host': '192.168.0.2',
            'server.socket_port': 32401,
            'engine.autoreload.on': True,
            "tools.sessions.on": True,
            "tools.sessions.storage_class": cherrypy.lib.sessions.FileSession,
            "tools.sessions.storage_path": os.path.join(baseDir, "data", "sessions"),
            "tools.sessions.timeout": 525600,
            "tools.sessions.name": "kitana_session_id",
            'tools.baseurloverride.baseurl': prefix,
            'tools.baseurloverride.on': prefix != "/"
        }
    )

    SassCompilerPlugin(cherrypy.engine).subscribe()
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "templates", "**")))
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "static", "sass", "**")))
    cherrypy.tools.baseurloverride = BaseUrlOverride()
    conf = {
        '/': {
            "tools.sessions.on": True,
            # 'tools.staticdir.root': os.path.abspath(os.getcwd())

        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(baseDir, "static")
        }
    }
    kitana = Kitana(prefix=prefix)
    env.globals['url'] = kitana.template_url

    cherrypy.engine.start()
    cherrypy.engine.publish('compile_sass')
    cherrypy.tree.mount(kitana, prefix, conf)

    cherrypy.engine.signals.subscribe()
    cherrypy.engine.block()
