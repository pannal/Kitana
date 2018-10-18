# coding=utf-8

import argparse
import textwrap as _textwrap
import re


class MultilineFormatter(argparse.HelpFormatter):
    def __init__(self, *args, **kwargs):
        super(MultilineFormatter, self).__init__(*args, **kwargs)
        self._whitespace_matcher = re.compile(r'(?![\n])\s+', re.ASCII)

    def _fill_text(self, text, width, indent):
        text = self._whitespace_matcher.sub(' ', text).strip()
        paragraphs = text.split('\n')
        multiline_text = ''
        for paragraph in paragraphs:
            formatted_paragraph = _textwrap.fill(paragraph, width, initial_indent=indent, subsequent_indent=indent) + \
                                  '\n'
            multiline_text = multiline_text + formatted_paragraph
        return multiline_text
