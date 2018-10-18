# coding=utf-8

import cherrypy

MESSAGE_TYPES = {
    "INFO": "info",
    "WARNING": "warning",
    "ERROR": "danger",
    "SUCCESS": "success",
    "default": "primary",
    "SECONDARY": "secondary",
}


def message(msg, _type="default"):
    if not cherrypy.session.get("messages"):
        cherrypy.session["messages"] = []

    messages = cherrypy.session["messages"]
    messages.append({"text": msg, "type": MESSAGE_TYPES.get(_type, MESSAGE_TYPES["default"])})
    cherrypy.session["messages"] = messages


def render_messages():
    if not cherrypy.session.get("messages", None) or not cherrypy.session["messages"]:
        return []

    messages = cherrypy.session["messages"][:]
    cherrypy.session["messages"] = None
    return messages
