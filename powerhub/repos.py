import subprocess
import os
import urllib.request
from urllib.parse import urlparse
from powerhub.directories import directories

repositories = {
    "AdrianVollmer/PowerSploit": "https://github.com/AdrianVollmer/PowerSploit.git",
    "SharpHound.exe": "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe",  # noqa
    "SharpHound.ps1": "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1",  # noqa
    "ASREPRoast.ps1": "https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1",
    "samratashok/Nishang": "https://github.com/samratashok/nishang.git",
    "S3cur3Th1sSh1t/PowerSharpPack": "https://github.com/S3cur3Th1sSh1t/PowerSharpPack",
    "r3motecontrol/Ghostpack Binaries": "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries",  # noqa
}


def install_repo(repo, custom_repo=None):
    """Download a repository; custom repositories have precedence"""
    if custom_repo:
        return install_repo_from_url(custom_repo)
    else:
        return install_repo_from_url(repositories[repo])


def install_repo_from_url(url):
    """Determine the type of a module and install it accordingly"""
    parsed_url = urlparse(url)
    basename = os.path.basename(parsed_url.path)
    if basename.endswith('.git'):
        return git_clone(url)
    elif basename.endswith('.ps1') or basename.endswith('.exe'):
        return download(url)
    else:
        raise Exception("Unknown extension: %s" % url)


def git_clone(url):
    """Installs a git repository"""
    dest_dir = directories.MOD_DIR
    if os.path.isdir(dest_dir):
        raise Exception("Directory already exists: %s" % dest_dir)
    subprocess.check_output(['git', 'clone', '--depth', '1', url, dest_dir],
                            stderr=subprocess.STDOUT)


def download(url):
    """Downloads a module that is not a git repository"""
    parsed_url = urlparse(url)
    basename = os.path.basename(parsed_url.path)
    response = urllib.request.urlopen(url)
    data = response.read()
    filename = os.path.join(directories.MOD_DIR, basename)
    if os.path.isfile(filename):
        raise Exception("File already exists: %s" % filename)
    with open(filename, 'wb') as f:
        f.write(data)
