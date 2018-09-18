#!/usr/bin/python3

import os
import cherrypy
import requests
import xmltodict
import glob
import json

from jinja2 import Environment, PackageLoader, select_autoescape, contextfunction

from plugins.SassCompilerPlugin import SassCompilerPlugin

env = Environment(
    loader=PackageLoader('kitana', 'templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

template = env.get_template('index.jinja2')


class BaseUrlOverride(cherrypy.Tool):

    def __init__(self):
        cherrypy.Tool.__init__(self, 'before_request_body', self.setbaseurl)

    def setbaseurl(self, baseurl=None):
        if baseurl:
            cherrypy.request.base = baseurl


class Kitana(object):
    BASE_URL = "http://127.0.0.1:32400/"
    PRODUCT_IDENTIFIER = "Kitana"
    VERSION = "0.1"
    CLIENT_IDENTIFIER = "{}_{}".format(PRODUCT_IDENTIFIER, VERSION)

    def __init__(self, prefix="/"):
        self.prefix = prefix
        self.plex_token = None

    def template_url(self, url):
        if not url.startswith(self.prefix):
            return self.prefix + url
        return url

    def plex_dispatch(self, path="video/subzero"):
        headers = {
            "X-Plex-Token": self.plex_token
        }
        data = requests.get(self.BASE_URL + path, headers=headers)
        content = xmltodict.parse(data.content, attr_prefix="")
        #print(json.dumps(content["MediaContainer"]))
        return template.render(data=content["MediaContainer"])

    @property
    def plex_token(self):
        token = cherrypy.session.get("plex_token")
        if not token:
            raise cherrypy.HTTPRedirect("/token")
        return token

    @plex_token.setter
    def plex_token(self, value):
        if not value:
            return
        cherrypy.session["plex_token"] = value

    @cherrypy.expose("token")
    def get_plex_token(self, username=None, password=None):
        if username and password:
            r = requests.post("https://plex.tv/users/sign_in.json", {
                "user[login]": username,
                "user[password]": password,
            }, headers={
                "X-Plex-Client-Identifier": self.CLIENT_IDENTIFIER,
                "X-Plex-Product": self.PRODUCT_IDENTIFIER,
                "X-Plex-Version": self.VERSION
            })
            r.raise_for_status()
            self.plex_token = r.json()["user"]["authToken"]
            raise cherrypy.HTTPRedirect("/")

        template = env.get_template('token.jinja2')
        return template.render()

    @cherrypy.expose
    def default(self, *args, **kwargs):
        query_params = "&".join("=".join([k, v]) for k, v in kwargs.items())
        path = "/".join(args) + ("?" + query_params if query_params else "")
        print(args, path)
        kw = {}
        if path:
            kw["path"] = path
        return self.plex_dispatch(**kw)


if __name__ == "__main__":
    baseDir = os.path.dirname(os.path.abspath(__file__))
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
            # 'tools.baseurloverride.baseurl': "/peter",
            # 'tools.baseurloverride.on': True
        }
    )
    prefix = "/"

    SassCompilerPlugin(cherrypy.engine).subscribe()
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "templates", "**")))
    cherrypy.engine.autoreload.files.update(glob.glob(os.path.join(baseDir, "static", "sass", "**")))
    #cherrypy.tools.baseurloverride = BaseUrlOverride()
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
