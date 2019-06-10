#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#  import os
#  import tempfile
import sys

import pytest

TEST_URI = 'foobar'


@pytest.fixture
def flask_app():
    sys.argv = ['./powerhub.py', TEST_URI, '--no-auth']
    from powerhub import flask
    flask_app = flask.app.test_client()
    yield flask_app


def test_initial_redirection(flask_app):
    response = flask_app.get('/')
    assert b"Redirecting..." in response.data
    assert b'<a href="//%s:' % TEST_URI.encode() in response.data


def test_hub_page(flask_app):
    response = flask_app.get('/hub')
    assert b"PowerHub" in response.data
    assert b"Hub" in response.data
    assert b"Paste this" in response.data
