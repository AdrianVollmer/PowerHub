#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import tempfile
import shutil
import sys
import re

import pytest

TEST_URI = 'foobar'
NEW_XDG_DATA_HOME = os.path.join(os.sep, 'tmp', 'ph_test')
os.environ["XDG_DATA_HOME"] = NEW_XDG_DATA_HOME
shutil.rmtree(NEW_XDG_DATA_HOME)
os.makedirs(NEW_XDG_DATA_HOME)


@pytest.fixture
def flask_app():
    sys.argv = ['./powerhub.py', TEST_URI, '--no-auth']
    temp_db = tempfile.mkstemp()[1]
    from powerhub import flask
    flask.cb.update()  # ensure table exists
    flask_app = flask.app.test_client()
    yield flask_app
    os.remove(temp_db)


def test_initial_redirection(flask_app):
    response = flask_app.get('/')
    assert b"Redirecting..." in response.data
    assert b'<a href="/hub' in response.data


def test_hub_page(flask_app):
    response = flask_app.get('/hub')
    assert b"PowerHub" in response.data
    assert b"Hub" in response.data
    assert b"Paste this" in response.data


def test_receiver_page(flask_app):
    response = flask_app.get('/receiver')
    assert b"PowerHub" in response.data
    assert b"Receiver" in response.data


def test_clipboard_page(flask_app):
    response = flask_app.get('/clipboard')
    assert b"PowerHub" in response.data
    assert b"Clipboard" in response.data
    assert b"Clipboard is empty" in response.data


def test_clipboard_add_del(flask_app):
    import cgi
    reps = 8
    content = '<strong>NO HTML</strong> allowed here'
    response = flask_app.get('/clipboard').data.decode()
    entry_count = response.count('card-text')
    test_count = response.count(cgi.escape(content))
    for i in range(reps):
        response = flask_app.post('/clipboard/add', data={
            'content': content,
        }, follow_redirects=False)
        assert response.status == '302 FOUND'
    response = flask_app.get('/clipboard').data.decode()
    assert "Delete all" in response
    assert "Export" in response
    new_entry_count = response.count('card-text')
    new_test_count = response.count(cgi.escape(content))
    assert cgi.escape(content) in response
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

#  TODO:
#      * retrieve download cradle
#      * stager generation
#      * test proxy including ssl
#      * test webdav
#      * basic authentication
#      * parsing
#      * reverse shell
#      * upload function

#  def test_argparse(capsys):
#      sys.argv = ['./powerhub.py', '--help']
#      from powerhub.args import parser
#      parser.parse_args()
#      captured = capsys.readouterr()
#      assert "PowerShell" in captured.err
