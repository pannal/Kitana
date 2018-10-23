# coding=utf-8
import contextlib
import os

from cherrypy.lib.sessions import FileSession as _FileSession


class FileSession(_FileSession):
    def release_lock(self, path=None):
        """Release the lock on the currently-loaded session data."""
        self.lock.close()
        with contextlib.suppress(FileNotFoundError, PermissionError):
            os.remove(self.lock._path)
        self.locked = False
