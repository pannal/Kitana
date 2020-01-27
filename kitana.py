#!/usr/bin/python3
import hashlib
import os
import io
import platform
import cherrypy
import requests
import xmltodict
import glob
import json
import uuid
import urllib
import argparse
import traceback

from collections import OrderedDict
from cherrypy import HTTPRedirect
from cherrypy.process.plugins import Monitor
from cherrypy.lib import static
from jinja2 import Environment, PackageLoader, select_autoescape
from urllib.parse import urlparse
from furl import furl
from requests import HTTPError, Timeout
from distutils.util import strtobool

from plugins.SassCompilerPlugin import SassCompilerPlugin
from tools.urls import BaseUrlOverride
from tools.cache import BigMemoryCache
from util.argparse import MultilineFormatter
from util.messages import message, render_messages
from util.update import update_check, LooseVersion
from util.sessions import FileSession
from util.str_util import mask_str, mask_url

env = Environment(
    loader=PackageLoader('kitana', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

template = env.get_template('index.jinja2')
settings_template = env.get_template('settings.jinja2')
isWin32 = os.name == "nt"


@cherrypy.tools.register('before_handler')
def maintenance():
    if kitana.has_update:
        message("Version {} is available. Please update{}".format(kitana.has_update,
                                                                  " your docker container"
                                                                  if kitana.running_as == "docker" else ""),
                persistent=True, data={"version": kitana.VERSION, "new_version": kitana.has_update})
        kitana.has_update = False

    if not kitana.maintenance_ran:
        try:
            kitana.run_maintenance()
        except:
            pass
        kitana.maintenance_ran = True


class Kitana(object):
    PRODUCT_IDENTIFIER = "Kitana"
    VERSION = "0.3.1-1"
    CLIENT_IDENTIFIER_BASE = "{}_{}".format(PRODUCT_IDENTIFIER, VERSION)
    initialized = False
    timeout = 5
    plextv_timeout = 15
    proxy_assets = True
    default_plugin_identifier = None
    running_as = "standalone"
    maintenance_ran = False
    has_update = False
    only_owned = True
    version_hash = hashlib.md5(VERSION.encode("utf-8")).hexdigest()[:7]

    def __init__(self, prefix="/", timeout=5, plextv_timeout=15, proxy_assets=True, plugin_identifier=None,
                 language="en", only_owned=True, running_as="standalone"):
        self.initialized = False

        self.prefix = prefix
        self.has_update = False
        self.maintenance_ran = False
        self.plex_token = None
        self.username = None
        self.server_name = None
        self.connection = None
        self.plugin = None
        self.plugins = None
        self.messages = None
        self.session = requests.Session()
        self.timeout = timeout
        self.language = language
        self.plextv_timeout = plextv_timeout
        self.req_defaults = {"timeout": self.timeout}
        self.proxy_assets = proxy_assets
        self.only_owned = only_owned
        self.default_plugin_identifier = plugin_identifier
        self.running_as = running_as
        self.initialized = True

    @classmethod
    def get_running_as(cls):
        if os.path.exists("/.dockerenv"):
            return "docker"
        elif os.path.exists(".git"):
            return "git"
        return "standalone"

    def template_url(self, url, **kw):
        if not url:
            return

        has_query = bool(urlparse(url).query)
        if (url.startswith("/:") and not url.endswith("/prefs")) or url.startswith("/library"):
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

    def static_url(self, url, **kw):
        f = furl(url)
        base, ext = os.path.splitext(str(f.path))
        f.set(path=".".join([base, self.version_hash]) + ext)
        return cherrypy.url(f.url)

    def is_url(self, url):
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def _dispatch(self, path, data=None):
        headers = {
            "X-Plex-Token": self.plex_token,
            "X-Plex-Language": self.language,
        }
        r = self.session.get(self.server_addr + path, headers=headers, params=data, **self.req_defaults)
        r.raise_for_status()
        return r

    def plex_dispatch(self, path):
        r = self._dispatch(path)

        content = xmltodict.parse(r.content, attr_prefix="", force_list=("Video", "Directory"))
        return content["MediaContainer"]

    def merge_plugin_data(self, data, keys=("Video", "Directory")):
        out = []
        for key in keys:
            if key in data and data[key]:
                out += data[key]
            data[key] = None

        return out

    def render_plugin(self, path, template=template, merge_item_keys=("Video", "Directory"), only_return_items=False):
        content = self.plex_dispatch(path)

        try:
            has_content = int(content["size"]) > 0
        except ValueError:
            has_content = False

        if not has_content:
            redirect = content.get("title2", None)
            # this is basically meant for SZ. title2 can contain a full URL to which we will redirect
            if redirect and self.is_url(redirect):
                if self.connections:
                    f = furl(redirect)

                    # try finding the current PMS in the link
                    is_current_pms = filter(lambda c: c["address"] == f.host or f.host in c["url"], self.connections)
                    if is_current_pms:
                        # use current PMS connection for the link
                        con = furl(self.server_addr)
                        f.host = con.host
                        f.port = con.port
                        redirect = f
                        r = requests.get(f)

                        # special handling for data
                        if r.headers['content-type'] != 'text/html':
                            data = io.BytesIO(r.content)
                            # set headers
                            for hdr in ("Content-Type", "Content-Disposition", "Content-Length"):
                                cherrypy.response.headers[hdr] = r.headers[hdr]

                            # serve
                            return static.serve_fileobj(data)
                raise cherrypy.HTTPRedirect(redirect)

            message("No plugin data returned", "WARNING")
            print("No plugin data returned, returning to plugin selection")
            self.plugin = None
            raise cherrypy.HTTPRedirect(cherrypy.url("/"))

        items = self.merge_plugin_data(content, keys=merge_item_keys)
        if only_return_items:
            return items

        return template.render(data=content, items=items, **self.default_context)

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
            "running_as": self.running_as,
        }

    @property
    def messages(self):
        return cherrypy.session.get("messages", [])

    @messages.setter
    def messages(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["messages"] = value

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
            raise cherrypy.HTTPRedirect(cherrypy.url("/token"))
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
    def connections(self):
        return cherrypy.session.get("connections")

    @connections.setter
    def connections(self, value):
        if not self.initialized and not value:
            return
        cherrypy.session["connections"] = value

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
        return OrderedDict([
            ("Accept", "application/json"),
            ("X-Plex-Product", self.PRODUCT_IDENTIFIER),
            ("X-Plex-Version", self.VERSION),
            ("X-Plex-Client-Identifier", self.client_identifier),
            ("X-Plex-Platform", platform.system()),
            ("X-Plex-Platform-Version", platform.release()),
            ("X-Plex-Model", self.PRODUCT_IDENTIFIER),
            ("X-Plex-Device", "{} {}".format(platform.system(), platform.release())),
            ("X-Plex-Device-Name", "Kitana ({})".format(self.running_as)),
            ("X-Plex-Device-Screen-Resolution", "1920x1080"),
            ("X-Plex-Language", "en")]
        )

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
        try:
            r = self.session.get("https://plex.tv/api/resources?includeHttps=1&includeRelay=1",
                                 headers=self.full_headers,
                                 timeout=self.plextv_timeout)
            r.raise_for_status()
        except (HTTPError, Timeout) as e:
            if isinstance(e, HTTPError):
                if e.response.status_code == 401:
                    self.plex_token = None
                    self.server_name = None
                    self.connection = None
                    print("Access denied when accessing {}, going to login".format(self.server_name))
                    raise cherrypy.HTTPRedirect(cherrypy.url("/token"))
            raise

        content = xmltodict.parse(r.content, attr_prefix="", force_list=("Device", "Connection"))
        servers = OrderedDict()
        # import pprint
        # pprint.pprint(content)
        use_connection = None
        connections = []
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
                    if self.only_owned and not device["owned"] == "1":
                        continue

                    servers[device["name"]] = {"connections": [], "owned": device["owned"] == "1",
                                               "publicAddress": device["publicAddress"],
                                               "publicAddressMatches": public_address_matches}

                if blacklist_addr and connection["uri"] in blacklist_addr:
                    print("{}: {} on blacklist, skipping".format(mask_str(device["name"]), mask_url(connection["uri"])))
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
                        connections = device["Connection"]
                        break

        if server_name and use_connection:
            self.server_name = server_name
            self.connection = use_connection
            self.connections = connections
            server_addr = use_connection["uri"]

            print("Server set to: {}, {}".format(mask_str(server_name), mask_url(server_addr)))
            print("Verifying {}: {}".format(mask_str(server_name), mask_url(server_addr)))
            try:
                self.session.get(self.server_addr + "servers", headers=self.full_headers, **self.req_defaults)
            except HTTPError as e:
                if e.response.status_code == 401:
                    self.plex_token = None
                    self.server_name = None
                    self.connection = None
                    print("Access denied when accessing {}, going to login".format(mask_str(self.server_name)))
                    raise cherrypy.HTTPRedirect(cherrypy.url("/token"))
            except Timeout as e:
                if not blacklist_addr:
                    blacklist_addr = []
                blacklist_addr.append(server_addr)
                print("{}: Blacklisting {} due to: {!r}".format(mask_str(server_name), mask_url(server_addr), type(e)))
                return self.discover_pms(server_name=server_name, server_addr=None, blacklist_addr=blacklist_addr)

            print("Verified {}: {}".format(mask_str(server_name), mask_url(server_addr)))
            self.plugin = None
            message("Successfully connected to {}".format(self.server_name), "SUCCESS")
            raise cherrypy.HTTPRedirect(cherrypy.url("/"))

        return servers

    @property
    def server_plugins(self):
        if not self.server_addr:
            con = self.connection.copy()
            con["uri"] = mask_url(con.get("uri", ""))
            con["address"] = mask_str(con.get("address", ""))

            print("No server address set, redirecting to root. Connection: {!r}".format(con))
            raise cherrypy.HTTPRedirect(cherrypy.url("/"))
        return self.plex_dispatch("channels/all")

    @cherrypy.expose
    @cherrypy.tools.maintenance()
    def servers(self, server_name=None, server_addr=None):
        servers = self.discover_pms(server_name=server_name, server_addr=server_addr)
        template = env.get_template('servers.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), servers=servers, **self.default_context)

    @cherrypy.expose
    @cherrypy.tools.maintenance()
    def choose_plugin(self, key=None, identifier=None, default_identifier=None):
        plugins = []
        try:
            plugins = self.plugins = self.server_plugins.get("Directory", [])
        except HTTPError as e:
            if e.response.status_code == 401:
                print("Access denied when accessing plugins on {}, going to server selection".format(
                    mask_str(self.server_name)))
                message("Access denied for plugins on {}".format(self.server_name), "ERROR")
                raise cherrypy.HTTPRedirect(cherrypy.url("/servers"))

        if (key and identifier) or default_identifier:
            ident = identifier or default_identifier
            for plugin in plugins:
                if plugin["identifier"] == ident:
                    self.plugin = plugin

                    print("Plugin chosen: {}".format(plugin["title"]))
                    raise cherrypy.HTTPRedirect(cherrypy.url("/"))

        template = env.get_template('plugins.jinja2')

        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context)

    @cherrypy.expose("token")
    @cherrypy.tools.maintenance()
    def get_plex_token(self, username=None, password=None, token=None):
        if username and password:
            r = self.session.post("https://plex.tv/users/sign_in.json", {
                "user[login]": username,
                "user[password]": password,
            }, headers=self.plex_headers, **self.req_defaults)
            try:
                r.raise_for_status()
            except HTTPError as e:
                if e.response.status_code == 401:
                    message("Wrong username and/or password", "ERROR")
            else:
                self.plex_token = r.json()["user"]["authToken"]
                print("Token received via credentials login")
                raise cherrypy.HTTPRedirect(cherrypy.url("/"))

        if token:
            self.plex_token = token
            print("Token received via plex.tv auth")
            return json.dumps({"url": cherrypy.url(self.prefix)})

        template = env.get_template('token.jinja2')
        return template.render(plex_headers_json=json.dumps(self.plex_headers), **self.default_context)

    @cherrypy.expose
    def logout(self):
        self.plex_token = None
        self.server_name = None
        self.connection = None
        raise cherrypy.HTTPRedirect(cherrypy.url("/"))

    @cherrypy.expose
    def pms_asset(self, url):
        url = urllib.parse.unquote_plus(url)
        r = self.session.get(self.server_addr + url, headers=self.full_headers)
        cherrypy.response.headers['Content-Type'] = r.headers.get("Content-Type", "image/jpg")
        return r.content

    def run_maintenance(self):
        # clear obsolete update messages
        messages = []
        seen = []
        for msg in self.messages[:]:
            if msg["persistent"] and msg["data"] and "version" in msg["data"]:
                if LooseVersion(kitana.VERSION) >= LooseVersion(msg["data"]["new_version"]):
                    continue

            if msg["text"] not in seen:
                messages.append(msg)
                seen.append(msg["text"])

        self.messages = messages

    @staticmethod
    def normalize_post_ret_value(val):
        if val in ("on", True):
            return "true"
        elif val in (None,):
            return "false"
        return val

    @cherrypy.expose()
    def plugin_prefs(self, *args, **kwargs):
        self.ensure_pms_data()
        url = ":/plugins/{}/prefs".format(self.plugin["identifier"])
        if cherrypy.request.method == "POST":
            items = self.render_plugin(url, settings_template, merge_item_keys=("Setting",), only_return_items=True)
            diff = {}
            for item in items:
                new_val = Kitana.normalize_post_ret_value(kwargs.get(item["id"]))
                if item["value"] != new_val:
                    diff[item["id"]] = new_val
            if diff:
                path = "{}/:/prefs/set".format(self.plugin["key"][1:])
                r = self._dispatch(path, data=diff)
                if r.status_code == 200:
                    message("Settings saved", "SUCCESS")
                else:
                    message("Something went wrong", "ERROR")
                raise cherrypy.HTTPRedirect(cherrypy.url("/"))
            else:
                print("No changed settings")
                message("No settings have been changed", "SECONDARY")
                raise cherrypy.HTTPRedirect(cherrypy.url("/"))
        else:
            return self.render_plugin(url, settings_template, merge_item_keys=("Setting",))

    @cherrypy.expose
    def plugin_restart(self, *args, **kwargs):
        self.ensure_pms_data()
        path = ":/plugins/{}/restart".format(self.plugin["identifier"])
        r = self._dispatch(path)
        if r.status_code == 200:
            message("Plugin restart triggered", "SUCCESS")
        else:
            message("Something went wrong when trying to restart the plugin", "ERROR")
        raise cherrypy.HTTPRedirect(cherrypy.url("/"))


    @cherrypy.expose
    @cherrypy.tools.maintenance()
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
                    message("Access denied on {}".format(self.server_name), "ERROR")
                    print("Access denied when accessing {},"
                          " going to server selection".format(mask_str(self.server_name)))
                    self.server_name = None
                    self.connection = None
                    raise cherrypy.HTTPRedirect(cherrypy.url("/servers"))
                elif e.response.status_code == 404:
                    raise cherrypy.HTTPRedirect(cherrypy.url("/plugins"))

            else:
                message("Timeout on {}".format(self.server_name), "WARNING")

            print("Error when connecting to '{}', trying other connection to: {}".format(mask_url(self.server_addr),
                                                                                         mask_str(self.server_name)))
            return self.discover_pms(self.server_name)
        except HTTPRedirect:
            raise
        except:
            print("Something went wrong. {}".format(traceback.format_exc()))


parser = argparse.ArgumentParser(formatter_class=MultilineFormatter)

if __name__ == "__main__":
    baseDir = os.path.dirname(os.path.abspath(__file__))

    parser.register('type', bool, strtobool)
    parser.epilog = "BOOL can be:\n" \
                    "True: \"y, yes, t, true, True, on, 1\"\n" \
                    "False: \"n, no, f, false, False, off, 0\".\n\n" \
                    "[BOOL] indicates that when the switch but no value is given, True is used."

    parser.add_argument('-B', '--bind', type=str, default="0.0.0.0:31337",
                        help="Listen on address:port (default: 0.0.0.0:31337)",
                        metavar="HOST:PORT")
    parser.add_argument('-a', '--autoreload', type=bool, default=False, metavar="BOOL", nargs="?", const=True,
                        help="Watch project files for changes and auto-reload? (default: False)")
    parser.add_argument('-i', '--plugin-identifier', type=str, default="com.plexapp.agents.subzero",
                        metavar="PLUGIN_IDENTIFIER",
                        help="The default plugin/channel to view on a server (default: com.plexapp.agents.subzero)")
    parser.add_argument('-l', '--plugin-language', type=str, default="en",
                        metavar="LANGUAGE",
                        help="The language to request when interacting with plugins (default: en)")
    parser.add_argument('-p', '--prefix', type=str, default="/", help="Prefix to handle; used for reverse proxies "
                                                                      "normally (default: \"/\")")
    parser.add_argument('-P', '--behind-proxy', type=bool, default=False, nargs="?", const=True, metavar="BOOL",
                        help="Assume being ran behind a reverse proxy (default: False)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-PH', '--proxy-host-var', type=str, nargs='?', const="Host", metavar="PROXY_HOST_VAR",
                       help="When behind reverse proxy, get host from this var "
                            "(NGINX: \"Host\", Squid: \"Origin\", Lighty/Apache: "
                            "\"X-Forwarded-Host\", IIS: \"Host\" (see README)) "
                            "(default: \"Host\")")
    group.add_argument('-PB', '--proxy-base', type=str, default=None,
                       help="When behind a reverse proxy, assume "
                            "this base URI instead of the bound address "
                            "(e.g.: http://host.com; no slash at the end). "
                            "Do *not* include the :prefix: here. (default: \"Host (NGINX)\")")
    parser.add_argument('--shadow-assets', type=bool, default=not isWin32, metavar="BOOL", nargs="?", const=True,
                        help="Pass PMS assets through the app to avoid exposing the plex token? (default: {})"
                        .format(not isWin32))
    parser.add_argument('-t', '--timeout', type=int, default=15,
                        help="Connection timeout to the PMS (default: 5)")
    parser.add_argument('-pt', '--plextv-timeout', type=int, default=25,
                        help="Connection timeout to the Plex.TV API (default: 15)")
    parser.add_argument('--allow-not-owned', type=bool, default=False, metavar="BOOL", nargs="?", const=True,
                        help="Allow access to not-owned servers? (default: False)")

    args = parser.parse_args()
    if args.proxy_base and args.proxy_host_var:
        parser.error("--proxy-base and --proxy-host-var can't be specified together")

    elif (args.proxy_base or args.proxy_host_var) and not args.behind_proxy:
        print("Assuming --behind-proxy, because {} is specified".format(
            "--proxy-base" if args.proxy_base else "--proxy-host-var"))
        args.behind_proxy = True

    host, port = args.bind.rsplit(":", 1) if ":" in args.bind else (args.bind, 31337)

    prefix = args.prefix

    if isWin32:
        args.autoreload = False

    sessions_dir = os.path.join(baseDir, "data", "sessions")
    if not os.path.exists(sessions_dir):
        try:
            os.makedirs(sessions_dir, exist_ok=True)
        except:
            print("{} doesn't exist and couldn't be created".format(sessions_dir))

    cherrypy.config.update(
        {
            'server.socket_host': host,
            'server.socket_port': int(port),
            'engine.autoreload.on': args.autoreload,
            'log.screen': True,
        }
    )

    SassCompilerPlugin(cherrypy.engine).subscribe()
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "templates", "**")))
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "static", "sass", "**")))
    cherrypy.tools.baseurloverride = BaseUrlOverride()

    if isWin32:
        from util.win32 import ConsoleCtrlHandler

        ConsoleCtrlHandler(cherrypy.engine).subscribe()

    conf = {
        "/": {
            "tools.sessions.on": True,
            "tools.sessions.storage_class": FileSession,
            "tools.sessions.storage_path": sessions_dir,
            "tools.sessions.timeout": 525600,
            "tools.sessions.name": "kitana_{}_session_id".format(Kitana.get_running_as()),
            "tools.sessions.locking": 'early',
            'tools.proxy.on': args.behind_proxy,
            'tools.proxy.local': args.proxy_host_var or "Host",
            'tools.proxy.base': args.proxy_base,
            # 'tools.staticdir.root': os.path.abspath(os.getcwd())
        },
        '/static': {
            'tools.caching.on': True,
            'tools.expires.on': True,
            'tools.expires.secs': 604800,
            'tools.staticdir.on': True,
            'tools.staticdir.dir': os.path.join(baseDir, "static"),
            "tools.sessions.on": False,
        },
        '/favicon.ico': {
            'tools.caching.on': True,
            'tools.expires.on': True,
            'tools.expires.secs': 604800,
            "tools.sessions.on": False,
            'tools.staticfile.on': True,
            'tools.staticfile.filename': os.path.join(baseDir, "static", "img", "favicon.ico"),
        },
        '/pms_asset': {
            'tools.caching.on': True,
            'tools.caching.delay': 604800,
            'tools.caching.cache_class': BigMemoryCache,
            'tools.expires.on': True,
            'tools.expires.secs': 604800,
            'tools.expires.force': True,
            'tools.etags.on': True,
            'tools.etags.autotags': True,
        }
    }

    versioned_asset_base_conf = {
        'tools.caching.on': True,
        'tools.expires.on': True,
        'tools.expires.secs': 604800,
        'tools.staticfile.on': True,
        "tools.sessions.on": False,
    }

    # add handlers for version-hash based assets
    for versioned_asset in ("css/main.css", "js/auth.js"):
        base, ext = os.path.splitext(versioned_asset)
        key = "/static/{}.{}{}".format(base, Kitana.version_hash, ext)
        conf.update(
            {
                key: dict(versioned_asset_base_conf,
                          **{'tools.staticfile.filename': os.path.join(baseDir, "static",
                                                                       versioned_asset.replace("/", os.sep))}, )
            }
        )

    kitana = Kitana(prefix=prefix, proxy_assets=args.shadow_assets, timeout=args.timeout,
                    plextv_timeout=args.plextv_timeout, plugin_identifier=args.plugin_identifier,
                    language=args.plugin_language, only_owned=not args.allow_not_owned,
                    running_as=Kitana.get_running_as())

    cherrypy.tree.mount(kitana, prefix, conf)
    cherrypy.engine.start()
    cherrypy.engine.publish('compile_sass')

    env.globals['url'] = kitana.template_url
    env.globals['static'] = kitana.static_url
    env.globals["render_messages"] = render_messages

    if kitana.running_as != "git":
        Monitor(cherrypy.engine, lambda: update_check(kitana), frequency=3600 * 6, name="UpdateCheck").subscribe()
        update_check(kitana)

    cherrypy.engine.signals.subscribe()
    cherrypy.engine.block()
