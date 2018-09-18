# -*- coding: future_fstrings -*-

import cherrypy
from cherrypy.process import wspbus, plugins
from pathlib import Path
import sass
import os
import shutil

__author__ = "Randy Yang (https://www.gitlab.com/randyyaj)"
__license__ = "MIT"
__version__ = "0.1.0"

class SassCompilerPlugin(plugins.SimplePlugin):
    """
    Custom Sass Compiler Plugin for cherrypy. Uses libsass to compile.

    Searches the whole project for any sass directories and creates a css
    directory in the same location with the compiled sass to css files.

    Register this plugin after the cherrypy.engine.start() block in your
    webservice or place it in your main function in your app.
    """
    def __init__(self, bus):
        plugins.SimplePlugin.__init__(self, bus)

    def start(self):
        self.bus.log('Starting SassCompilerPlugin')
        self.bus.subscribe("compile_sass", self.compile_sass)

    def stop(self):
        self.bus.log('Stopping SassCompilerPlugin')
        self.bus.unsubscribe("compile_sass", self.compile_sass)

    def compile_sass(self):
        cherrypy.log("Starting Sass Compile")
        for (dirpath, dirnames, filenames) in os.walk(os.getcwd()):
            if dirpath.endswith('/sass'):
                css_directory = Path(str(Path(dirpath).parent) + "/css")

                if not css_directory.exists():
                    Path.mkdir(css_directory)
                else:
                    shutil.rmtree(str(css_directory))
                    Path.mkdir(css_directory)

                cherrypy.log(f'{self.__class__.__name__}: Compiling {dirpath} to {str(css_directory)}')
                sass.compile(dirname=(dirpath, str(css_directory)), output_style='compressed')
