#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import sys
import re

import flask
import pytest

# https://stackoverflow.com/a/33515264/1308830
sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from test_init import TEST_URI, init_tests  # noqa


init_tests()


@pytest.fixture(scope="module")
def flask_app():
    temp_db = tempfile.mkstemp()[1]
    from powerhub.app import PowerHubApp
    app = PowerHubApp([TEST_URI, '--no-auth'])
    from powerhub.flask import app as blueprint
    flask_app = flask.Flask(__name__, static_url_path='/invalid', template_folder="../powerhub/templates")
    flask_app.register_blueprint(blueprint)
    flask_app = flask_app.test_client()
    yield flask_app
    os.remove(temp_db)
    app.stop()


def test_initial_redirection(flask_app):
    response = flask_app.get('/')
    assert b"Redirecting..." in response.data
    assert b'<a href="/hub' in response.data


def test_hub_page(flask_app):
    response = flask_app.get('/hub')
    assert b"PowerHub" in response.data
    assert b"Hub" in response.data
    assert b"This is the Hub" in response.data
    assert b"AMSI Bypass" in response.data


def test_clipboard_page(flask_app):
    response = flask_app.get('/clipboard')
    assert b"PowerHub" in response.data
    assert b"Clipboard" in response.data
    assert b"Clipboard is empty" in response.data


def test_clipboard_add_del(flask_app):
    try:
        from cgi import escape
    except ImportError:
        from html import escape
    reps = 8
    content = '<strong>NO HTML</strong> allowed here'
    response = flask_app.get('/clipboard').data.decode()
    entry_count = response.count('card-body')
    test_count = response.count(escape(content))
    for i in range(reps):
        response = flask_app.post('/clipboard/add', data={
            'content': content,
        }, follow_redirects=False)
        assert response.status == '302 FOUND'
    response = flask_app.get('/clipboard').data.decode()
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
        response = flask_app.post('/clipboard/delete', data={
            'id': e_id,
        }, follow_redirects=False)
        response = flask_app.get('/clipboard').data.decode()
        assert ('data-id="%s"' % e_id) not in response


def test_fileexchange_page(flask_app):
    from powerhub.directories import UPLOAD_DIR
    f = tempfile.NamedTemporaryFile("w+", dir=UPLOAD_DIR)
    size = 617
    f.write("0"*size)
    f.flush()
    response = flask_app.get('/fileexchange').data.decode()
    assert "PowerHub" in response
    assert "File Exchange" in response
    assert os.path.basename(f.name) in response
    assert "<td>%d</td>" % size in response


def test_static(flask_app):
    from powerhub.directories import STATIC_DIR
    f = tempfile.NamedTemporaryFile("w+", dir=STATIC_DIR)
    basename = os.path.basename(f.name)
    size = 617
    f.write("0"*size)
    f.flush()
    response = flask_app.get('/static/'+basename).data.decode()
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
