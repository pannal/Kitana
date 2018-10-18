#!/usr/bin/python3

import os
import platform
import textwrap
import traceback
from collections import OrderedDict

import cherrypy
import requests
import xmltodict
import glob
import json
import uuid
import urllib
import argparse

from jinja2 import Environment, PackageLoader, select_autoescape
from urllib.parse import urlparse
from cherrypy.lib.static import serve_file
from requests import HTTPError, Timeout
from distutils.util import strtobool

from plugins.SassCompilerPlugin import SassCompilerPlugin
from tools.urls import BaseUrlOverride
from tools.cache import BigMemoryCache
from util.argparse import MultilineFormatter

env = Environment(
    loader=PackageLoader('kitana', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

template = env.get_template('index.jinja2')


class Kitana(object):
    PRODUCT_IDENTIFIER = "Kitana"
    VERSION = "0.0.2"
    CLIENT_IDENTIFIER_BASE = "{}_{}".format(PRODUCT_IDENTIFIER, VERSION)
    initialized = False
    timeout = 5
    plextv_timeout = 15
    proxy_assets = True
    default_plugin_identifier = None

    def __init__(self, prefix="/", timeout=5, plextv_timeout=15, proxy_assets=True, plugin_identifier=None):
        self.initialized = False
        self.prefix = prefix
        self.plex_token = None
        self.username = None
        self.server_name = None
        self.connection = None
        self.plugin = None
        self.plugins = None
        self.session = requests.Session()
        self.timeout = timeout
        self.plextv_timeout = plextv_timeout
        self.req_defaults = {"timeout": self.timeout}
        self.proxy_assets = proxy_assets
        self.default_plugin_identifier = plugin_identifier
        self.initialized = True

    def template_url(self, url, **kw):
        has_query = bool(urlparse(url).query)
        if url.startswith("/:") or url.startswith("/library"):
            if self.proxy_assets:
                url = cherrypy.url("/pms_asset",
                                   qs={"url": urllib.parse.quote_plus(url[1:] if url.startswith("/") else url)})
            else:
                url = self.server_addr + url[1:]
                if has_query:
                    url += '&'
                else:
                    url += '?'
                url += "X-Plex-Token={}".format(self.plex_token)
            return url

        if not url.startswith("http") and not url.startswith(self.prefix):
            url = self.prefix + url

        if kw:
            url += ("?" if not has_query else "&") + "&".join("=".join([str(k), str(v)]) for k, v in kw.items())

        return url

    def plex_dispatch(self, path):
        headers = {
            "X-Plex-Token": self.plex_token
        }
        r = self.session.get(self.server_addr + path, headers=headers, **self.req_defaults)
        r.raise_for_status()
        content = xmltodict.parse(r.content, attr_prefix="")
        return content["MediaContainer"]

    def render_plugin(self, path):
        content = self.plex_dispatch(path)
        try:
            has_content = int(content["size"]) > 0
        except ValueError:
            has_content = False

        if not has_content:
            print("No plugin data returned, returning to plugin selection")
            self.plugin = None
            raise cherrypy.HTTPRedirect(self.prefix)

        return template.render(data=content, **self.default_context)

    @property
    def default_context(self):
        return {
            "logged_in": bool(cherrypy.session.get("plex_token")),
            "username": cherrypy.session.get("username"),
            "server_name": cherrypy.session.get("server_name"),
            "connection": cherrypy.session.get("connection"),
            "plugins": cherrypy.session.get("plugins"),
            "plugin": cherrypy.session.get("plugin"),
            "product_identifier": self.PRODUCT_IDENTIFIER,
            "version": self.VERSION,
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
            raise cherrypy.HTTPRedirect("{}/token".format(self.prefix))
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
        if not self.connection:
            return
        value = self.connection.get("uri", None)
        return value + "/" if value else None

    @property
    def connection(self):
        return cherrypy.session.get("connection", {})

    @connection.setter
    def connection(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["connection"] = value

    @property
    def plugin(self):
        return cherrypy.session.get("plugin", {})

    @plugin.setter
    def plugin(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["plugin"] = value

    @property
    def plugins(self):
        return cherrypy.session.get("plugins", {})

    @plugins.setter
    def plugins(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["plugins"] = value

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

        if not self.plugin or not self.plugins:
            raise cherrypy.HTTPRedirect(cherrypy.url("/choose_plugin",
                                                     qs={"default_identifier": self.default_plugin_identifier}))

    def discover_pms(self, server_name=None, server_addr=None, blacklist_addr=None):
        r = self.session.get("https://plex.tv/api/resources?includeHttps=1&includeRelay=1", headers=self.full_headers,
                             timeout=self.plextv_timeout)
        r.raise_for_status()
        content = xmltodict.parse(r.content, attr_prefix="")
        servers = OrderedDict()
        # import pprint
        # pprint.pprint(content)
        use_connection = None
        for device in content["MediaContainer"].get("Device", []):
            if device["provides"] != "server" or not bool(device["presence"]):
                continue

            public_address_matches = device["publicAddressMatches"] == "1"
            https_required = device["httpsRequired"] == "1"

            for connection in device["Connection"]:
                connection["unavailable"] = False
                if not public_address_matches and connection["local"] == "1":
                    continue

                elif https_required and connection["protocol"] != "https":
                    continue

                if device["name"] not in servers:
                    servers[device["name"]] = {"connections": [], "owned": device["owned"] == "1",
                                               "publicAddress": device["publicAddress"],
                                               "publicAddressMatches": public_address_matches}

                if blacklist_addr and connection["uri"] in blacklist_addr:
                    print("{}: {} on blacklist, skipping".format(device["name"], connection["uri"]))
                    connection["unavailable"] = True
                    continue

                servers[device["name"]]["connections"].append(connection)
                if server_name and server_name == device["name"]:
                    if server_addr and connection["uri"] == server_addr:
                        use_connection = connection

                    elif server_addr and server_addr == "relay" and connection.get("relay") == "1":
                        use_connection = connection

                    elif not server_addr:
                        use_connection = connection

                    if use_connection:
                        break

        if server_name and use_connection:
            self.server_name = server_name
            self.connection = use_connection
            server_addr = use_connection["uri"]

            print("Server set to: {}, {}".format(server_name, server_addr))
            print("Verifying {}: {}".format(server_name, server_addr))
            try:
                self.session.get(self.server_addr + "servers", headers=self.full_headers, **self.req_defaults)
            except HTTPError as e:
                if e.response.status_code == 401:
                    self.plex_token = None
                    self.server_name = None
                    self.connection = None
                    print("Access denied when accessing {}, going to login".format(self.server_name))
                    raise cherrypy.HTTPRedirect("{}/token".format(self.prefix))
            except Timeout as e:
                if not blacklist_addr:
                    blacklist_addr = []
                blacklist_addr.append(server_addr)
                print("{}: Blacklisting {} due to: {!r}".format(server_name, server_addr, e))
                return self.discover_pms(server_name=server_name, server_addr=None, blacklist_addr=blacklist_addr)

            print("Verified {}: {}".format(server_name, server_addr))
            self.plugin = None
            raise cherrypy.HTTPRedirect(self.prefix)

        return servers

    @property
    def server_plugins(self):
        return self.plex_dispatch("channels/all")

    @cherrypy.expose
    def servers(self, server_name=None, server_addr=None):
        servers = self.discover_pms(server_name=server_name, server_addr=server_addr)
        template = env.get_template('servers.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context, servers=servers)

    @cherrypy.expose
    def choose_plugin(self, key=None, identifier=None, default_identifier=None):
        plugins = []
        try:
            plugins = self.plugins = self.server_plugins.get("Directory", [])
        except HTTPError as e:
            if e.response.status_code == 401:
                print("Access denied when accessing {}, going to server selection".format(self.server_name))
                raise cherrypy.HTTPRedirect("{}/servers".format(self.prefix))

        if (key and identifier) or default_identifier:
            ident = identifier or default_identifier
            for plugin in plugins:
                if plugin["identifier"] == ident:
                    self.plugin = plugin

                    print("Plugin chosen: {}".format(plugin["title"]))
                    raise cherrypy.HTTPRedirect(self.prefix)

        template = env.get_template('plugins.jinja2')

        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context)

    @cherrypy.expose("token")
    def get_plex_token(self, username=None, password=None, token=None):
        if username and password:
            r = self.session.post("https://plex.tv/users/sign_in.json", {
                "user[login]": username,
                "user[password]": password,
            }, headers=self.plex_headers, **self.req_defaults)
            r.raise_for_status()
            self.plex_token = r.json()["user"]["authToken"]
            raise cherrypy.HTTPRedirect(self.prefix)

        if token:
            self.plex_token = token
            return json.dumps({"url": cherrypy.url(self.prefix)})

        template = env.get_template('token.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context)

    @cherrypy.expose
    def logout(self):
        self.plex_token = None
        self.server_name = None
        self.connection = None
        raise cherrypy.HTTPRedirect(self.prefix)

    @cherrypy.expose
    def pms_asset(self, url):
        url = urllib.parse.unquote_plus(url)
        r = self.session.get(self.server_addr + url, headers=self.full_headers)
        cherrypy.response.headers['Content-Type'] = r.headers.get("Content-Type", "image/jpg")
        return r.content

    @cherrypy.expose
    def default(self, *args, **kwargs):
        self.ensure_pms_data()

        query_params = "&".join("=".join([k, v]) for k, v in kwargs.items())
        path = "/".join(args) + ("?" + query_params if query_params else "")
        # print(args, path)
        if not path:
            path = self.plugin["key"][1:]

        try:
            return self.render_plugin(path)
        except (HTTPError, Timeout) as e:
            if isinstance(e, HTTPError):
                if e.response.status_code == 401:
                    print("Access denied when accessing {}, going to server selection".format(self.server_name))
                    self.server_name = None
                    self.connection = None
                    raise cherrypy.HTTPRedirect("{}/servers".format(self.prefix))
                elif e.response.status_code == 404:
                    raise cherrypy.HTTPRedirect("{}/plugins".format(self.prefix))

            print("Error when connecting to '{}', trying other connection to: {}".format(self.server_addr,
                                                                                         self.server_name))
            return self.discover_pms(self.server_name)


parser = argparse.ArgumentParser(formatter_class=MultilineFormatter)

if __name__ == "__main__":
    baseDir = os.path.dirname(os.path.abspath(__file__))

    parser.register('type', bool, strtobool)
    parser.epilog = "BOOL can be:\n" \
                    "True: \"y, yes, t, true, on, 1\"\n" \
                    "False: \"n, no, f, false, off, 0\".\n\n" \
                    "[BOOL] indicates that when no value is given, True is used."

    parser.add_argument('-B', '--bind', type=str, default="0.0.0.0:31337",
                        help="Listen on address:port (default: 0.0.0.0:31337)",
                        metavar="HOST:PORT")
    parser.add_argument('-a', '--autoreload', type=bool, default=False, metavar="BOOL", nargs="?", const=True,
                        help="Watch project files for changes and auto-reload? (default: False)")
    parser.add_argument('-i', '--plugin-identifier', type=str, default="com.plexapp.agents.subzero",
                        metavar="PLUGIN_IDENTIFIER",
                        help="The default plugin/channel to view on a server (default: com.plexapp.agents.subzero)")
    parser.add_argument('-p', '--prefix', type=str, default="/", help="Prefix to handle; used for reverse proxies "
                                                                      "normally (default: \"/\")")
    parser.add_argument('-P', '--behind-proxy', type=bool, default=False, nargs="?", const=True, metavar="BOOL",
                        help="Assume being ran behind a reverse proxy (default: False)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-PH', '--proxy-host-var', type=str, nargs='?', const="Host", metavar="PROXY_HOST_VAR",
                       help="When behind reverse proxy, get host from this var "
                            "(NGINX: \"Host\", Squid: \"Origin\", Lighty/Apache: \"X-Forwarded-Host\") "
                            "(default: \"Host\")")
    group.add_argument('-PB', '--proxy-base', type=str, default=None,
                       help="When behind a reverse proxy, assume "
                            "this base URI instead of the bound address "
                            "(e.g.: http://host.com; no slash at the end). "
                            "Do *not* include the :prefix: here. (default: \"Host (NGINX)\")")
    parser.add_argument('--shadow-assets', type=bool, default=True, metavar="BOOL", nargs="?", const=True,
                        help="Pass PMS assets through the app to avoid exposing the plex token? (default: True)")
    parser.add_argument('-t', '--timeout', type=int, default=5,
                        help="Connection timeout to the PMS (default: 5)")
    parser.add_argument('-pt', '--plextv-timeout', type=int, default=15,
                        help="Connection timeout to the Plex.TV API (default: 15)")

    args = parser.parse_args()
    if args.proxy_base and args.proxy_host_var:
        parser.error("--proxy-base and --proxy-host-var can't be specified together")

    elif (args.proxy_base or args.proxy_host_var) and not args.behind_proxy:
        print("Assuming --behind-proxy, because {} is specified".format(
            "--proxy-base" if args.proxy_base else "--proxy-host-var"))
        args.behind_proxy = True

    host, port = args.bind.rsplit(":", 1) if ":" in args.bind else (args.bind, 31337)

    prefix = args.prefix

    cherrypy.config.update(
        {
            'server.socket_host': host,
            'server.socket_port': int(port),
            'engine.autoreload.on': args.autoreload,
            "tools.sessions.on": True,
            "tools.sessions.storage_class": cherrypy.lib.sessions.FileSession,
            "tools.sessions.storage_path": os.path.join(baseDir, "data", "sessions"),
            "tools.sessions.timeout": 525600,
            "tools.sessions.name": "kitana_session_id",
            'tools.proxy.on': args.behind_proxy,
            'tools.proxy.local': args.proxy_host_var or "Host",
            'tools.proxy.base': args.proxy_base,
            # 'tools.baseurloverride.baseurl': prefix,
            # 'tools.baseurloverride.on': prefix != "/"
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
            'tools.staticdir.dir': os.path.join(baseDir, "static"),
        },
        '/pms_asset': {
            'tools.caching.on': True,
            'tools.caching.delay': 604800,
            'tools.caching.cache_class': BigMemoryCache,
            'tools.expires.on': True,
            'tools.expires.secs': 604800,
            'tools.expires.force': True,
        }
    }
    kitana = Kitana(prefix=prefix, proxy_assets=args.shadow_assets, timeout=args.timeout,
                    plextv_timeout=args.plextv_timeout, plugin_identifier=args.plugin_identifier)
    env.globals['url'] = kitana.template_url

    cherrypy.engine.start()
    cherrypy.engine.publish('compile_sass')
    cherrypy.tree.mount(kitana, prefix, conf)

    cherrypy.engine.signals.subscribe()
    cherrypy.engine.block()
