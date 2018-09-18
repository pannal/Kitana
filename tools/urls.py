# coding=utf-8
import cherrypy


class BaseUrlOverride(cherrypy.Tool):

    def __init__(self):
        cherrypy.Tool.__init__(self, 'before_request_body', self.setbaseurl)

    def setbaseurl(self, baseurl=None):
        if baseurl:
            cherrypy.request.base = baseurl