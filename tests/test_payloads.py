#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tempfile

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import BACKENDS, init_tests, execute_cmd  # noqa

init_tests()


@pytest.fixture
def parameters():
    with tempfile.TemporaryDirectory(
        prefix='powerhub_tests',
        ignore_cleanup_errors=True,
    ) as tmpdir:
        os.environ['XDG_DATA_HOME'] = tmpdir
        from powerhub.directories import init_directories
        init_directories(None, create_missing=True)

        args = {
            "launcher": "powershell",
            "amsi": "reflection",
            "transport": "http",
            "proxy": "false",
            "tlsv1.2": "false",
            "fingerprint": "true",
            "noverification": "false",
            "certstore": "false",
            "arch": "64bit",
            "natural": "false",
            "incremental": "false",
            "useragent": "false",
            "kex": 'embedded',
        }
        key = 'A'*16
        callback_urls = {
            'http': 'http://127.0.0.1',
            'https': 'https://127.0.0.1',
        }
        yield args, key, callback_urls


@pytest.fixture(
    params=list(k for k, v in BACKENDS.items() if v['psversion'] >= 5)
)
def backend(request):
    """Parameterize backends"""
    return BACKENDS[request.param]


def copy_and_execute(backend, filename, payload, interpreter=""):
    import tempfile
    if isinstance(payload, str):
        tmpf = tempfile.NamedTemporaryFile('w', delete=False)
    else:
        tmpf = tempfile.NamedTemporaryFile('wb', delete=False)
    tmpf.write(payload)
    tmpf.close()

    execute_cmd(backend, f"{tmpf.name} win10:C:/Windows/Temp/{filename}",
                copy=True)
    out = execute_cmd(backend, f"'{interpreter} C:/Windows/Temp/{filename}'")
    return out


def test_vbs(parameters, backend):
    from powerhub.payloads import create_vbs
    from powerhub.parameters import param_collection
    args, key, callback_urls = parameters

    args['launcher'] = 'vbs'
    param_collection.parse_get_args(args)
    filename, payload = create_vbs(param_collection, key, callback_urls)
    assert filename == 'powerhub-vbs-reflection-http.vbs'

    out = copy_and_execute(backend, filename, payload, "cscript.exe")
    assert "Windows Script Host" in out
    assert "error" not in out


def test_gcc(parameters, backend):
    from powerhub.payloads import create_exe
    from powerhub.parameters import param_collection
    args, key, callback_urls = parameters

    args['launcher'] = 'mingw32'
    param_collection.parse_get_args(args)
    filename, payload = create_exe(param_collection, key, callback_urls)
    assert filename == 'powerhub-mingw32-reflection-http-64bit.exe'
    assert b"DOS" in payload
    assert payload.startswith(b'MZ')

    out = copy_and_execute(backend, filename, payload)
    assert out == "1"


def test_mcs(parameters, backend):
    from powerhub.payloads import create_dotnet
    from powerhub.parameters import param_collection
    args, key, callback_urls = parameters

    args['launcher'] = 'dotnetexe'
    param_collection.parse_get_args(args)
    filename, payload = create_dotnet(param_collection, key, callback_urls)
    assert filename == 'powerhub-dotnetexe-reflection-http-64bit.exe'
    assert b"DOS" in payload
    assert payload.startswith(b'MZ')

    out = copy_and_execute(backend, filename, payload)

    assert out == ""
