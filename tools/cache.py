# coding=utf-8
from cherrypy.lib.caching import MemoryCache


class BigMemoryCache(MemoryCache):
    maxobj_size = 500000
    maxsize = 50000000
