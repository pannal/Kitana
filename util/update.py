# coding=utf-8

import traceback

from github import Github, GithubException
from distutils.version import StrictVersion


def _update_check(kitana):
    g = Github()
    repo = g.get_repo("pannal/Kitana")
    try:
        release = repo.get_latest_release()
    except GithubException:
        return

    if StrictVersion(kitana.VERSION) < StrictVersion(release.tag_name):
        kitana.has_update = release.tag_name


def update_check(kitana):
    try:
        _update_check(kitana)
    except:
        print("Update check failed")
        traceback.print_exc()
