#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import tempfile
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
            "launcher": "powershell",
            "amsi": "reflection",
            "transport": "http",
            "clip-exec": "none",
            "proxy": "false",
            "tlsv1.2": "false",
            "fingerprint": "true",
            "noverification": "false",
            "certStore": "false",
        },
        'HTTPS': {
            "flavor": "hub",
            "launcher": "powershell",
            "amsi": "reflection",
            "transport": "https",
            "clip-exec": "none",
            "proxy": "false",
            "tlsv1.2": "false",
            "fingerprint": "true",
            "noverification": "false",
            "certStore": "false",
        },
        'BASH': {
            "flavor": "hub",
            "launcher": "bash",
            "amsi": "reflection",
            "transport": "http",
            "clip-exec": "none",
            "proxy": "false",
            "tlsv1.2": "false",
            "fingerprint": "true",
            "noverification": "false",
            "certStore": "false",
        },
    }
    i = 0
    while i < 10:
        try:
            for k, v in param_set.items():
                response = requests.get(
                    f"http://{TEST_URI}:{PORT}/dlcradle",
                    params=v,
                    headers={'Accept': 'text/html'},
                ).text
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
    from powerhub.directories import directories
    for i in range(MAX_TEST_MODULE_PS1):
        with open(
            os.path.join(directories.MOD_DIR, "psmod%d.ps1" % i),
            "w"
        ) as f:
            f.write(func % {"n": i})


@pytest.fixture(scope="module")
def full_app():
    with tempfile.TemporaryDirectory(
        prefix='powerhub_tests',
        ignore_cleanup_errors=True,
    ) as tmpdir:
        os.environ['XDG_DATA_HOME'] = tmpdir

        from powerhub.args import parse_args
        from powerhub.app import PowerHubApp

        args = parse_args([TEST_URI, '--no-auth'])
        app = PowerHubApp(args)
        app.run(background=True)
        create_modules()

        yield get_stager()

        app.stop()


def test_stager(full_app):
    assert "New-Object Net.WebClient" in full_app['default']
    assert f"DownloadString('https://{TEST_URI}:" in full_app['default']
    assert (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback"
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


@pytest.fixture(scope="module", params=["win10"])
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
    out = execute_cmd(backend("ghm psmod53|fl;Invoke-Testfunc53"))
    assert "Test53" in out
    assert "psmod53" in out
    assert re.search("Name *: .*psmod53.ps1\r\n", out)
    assert re.search("Type *: ps1\r\n", out)
    assert re.search("N *: 53\r\n", out)
    assert re.search("Loaded *: True\r\n", out)


def test_load_hubmodule_range(backend):
    out = execute_cmd(
        backend(
            '$p="72-74,77,90-93";ghm $p;'
            "Invoke-Testfunc72;Invoke-Testfunc73;Invoke-Testfunc74;"
            "Invoke-Testfunc77;"
            "Invoke-Testfunc90;Invoke-Testfunc92;Invoke-Testfunc93;"
        )
    )
    assert "Test72" in out
    assert "Test73" in out
    assert "Test74" in out
    assert "Test77" in out
    assert "Test90" in out
    assert "Test93" in out


def test_upload(backend):
    from powerhub.directories import directories
    testfile = "testfile-%030x.dat" % random.randrange(16**30)
    out = execute_cmd(
        backend(('$p=Join-Path $env:TEMP "%s";'
                 + '[io.file]::WriteAllBytes($p,(1..255));'
                 + 'pth $p;rm $p') % testfile)
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(directories.UPLOAD_DIR, testfile), "rb") as f:
        data = f.read()
    assert data == bytes(range(1, 256))

    out = execute_cmd(
        backend('$p="FooBar123";$p|pth -name %s;' % testfile)
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(directories.UPLOAD_DIR, testfile+".1"), "rb") as f:
        data = f.read()
    assert data == b"FooBar123"
