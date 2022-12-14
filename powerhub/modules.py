import logging
import os

import magic

from powerhub.directories import MOD_DIR


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


def update_modules():
    """Import all modules as a list and assign global var `modules` to it"""

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

    global modules
    modules = result


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


update_modules()
