#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import sys
import re

import pytest

# https://stackoverflow.com/a/33515264/1308830
sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import TEST_URI, init_tests  # noqa


init_tests()


@pytest.fixture(scope="module")
def test_client():
    temp_db = tempfile.mkstemp()[1]

    from powerhub.app import PowerHubApp
    from powerhub.args import parse_args
    args = parse_args([TEST_URI, '--no-auth'])
    app = PowerHubApp(args)

    yield app.flask_app.test_client()

    os.remove(temp_db)
    app.stop()


def test_initial_redirection(test_client):
    response = test_client.get('/', headers={'Accept': 'text/html'})
    assert b"Redirecting..." in response.data
    assert b'<a href="/hub' in response.data


def test_hub_page(test_client):
    response = test_client.get('/hub', headers={'Accept': 'text/html'})
    assert b"PowerHub" in response.data
    assert b"Hub" in response.data
    assert b"This is the Hub" in response.data
    assert b"AMSI Bypass" in response.data


def test_clipboard_page(test_client):
    response = test_client.get('/clipboard', headers={'Accept': 'text/html'})
    assert b"PowerHub" in response.data
    assert b"Clipboard" in response.data
    assert b"Clipboard is empty" in response.data


def test_clipboard_add_del(test_client):
    try:
        from cgi import escape
    except ImportError:
        from html import escape
    reps = 8
    content = '<strong>NO HTML</strong> allowed here'
    response = test_client.get('/clipboard', headers={'Accept': 'text/html'}).data.decode()
    entry_count = response.count('card-body')
    test_count = response.count(escape(content))
    for i in range(reps):
        response = test_client.post(
            '/clipboard/add',
            data={'content': content},
            headers={'Accept': 'text/html'},
            follow_redirects=False,
        )
        assert response.status == '302 FOUND'
    response = test_client.get('/clipboard', headers={'Accept': 'text/html'}).data.decode()
    assert "Delete all" in response
    assert "Export" in response
    new_entry_count = response.count('card-body')
    new_test_count = response.count(escape(content))
    assert escape(content) in response
    assert entry_count == new_entry_count - reps
    assert test_count == new_test_count - reps

    # delete
    for i in range(reps):
        e_id = re.findall(r'data-id="([0-9]+)"', response)[-1]
        response = test_client.post(
            '/clipboard/delete',
            headers={'Accept': 'text/html'},
            data={
                'id': e_id,
            },
            follow_redirects=False,
        )
        response = test_client.get('/clipboard').data.decode()
        assert ('data-id="%s"' % e_id) not in response


def test_fileexchange_page(test_client):
    from powerhub.directories import directories
    f = tempfile.NamedTemporaryFile("w+", dir=directories.UPLOAD_DIR)
    size = 617
    f.write("0"*size)
    f.flush()
    response = test_client.get('/fileexchange', headers={'Accept': 'text/html'}).data.decode()
    assert "PowerHub" in response
    assert "File Exchange" in response
    assert os.path.basename(f.name) in response
    assert "<td>%d</td>" % size in response


def test_static(test_client):
    from powerhub.directories import directories
    f = tempfile.NamedTemporaryFile("w+", dir=directories.STATIC_DIR)
    basename = os.path.basename(f.name)
    size = 617
    f.write("0"*size)
    f.flush()
    response = test_client.get('/static/'+basename, headers={'Accept': 'text/html'}).data.decode()
    assert "0"*size == response

#  TODO:
#      * retrieve download cradle
#      * stager generation
#      * test proxy including ssl
#      * test webdav
#      * basic authentication
#      * parsing
#      * upload function

#  def test_argparse(capsys):
#      sys.argv = ['./powerhub.py', '--help']
#      from powerhub.args import parser
#      parser.parse_args()
#      captured = capsys.readouterr()
#      assert "PowerShell" in captured.err
