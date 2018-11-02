# coding=utf-8
from furl import furl


def mask_str(s, visible=4):
    if not s:
        return ""
    quarter = int(len(s) / 4)
    if visible > quarter:
        visible = quarter

    if not visible:
        return s[:1].ljust(len(s), "*")

    left = s[:visible]
    right = s[-visible:]
    center = s[visible:-visible]
    return left + len(center) * "*" + right


def mask_url(u):
    if not u:
        return ""
    f = furl(u)
    f._host = mask_str(f.host)
    return f.url
