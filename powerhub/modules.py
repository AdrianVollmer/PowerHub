import logging
import os
import threading

import magic
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

from powerhub.directories import directories


log = logging.getLogger(__name__)

modules = []
EXTENSIONS = [".ps1", ".ps1m", ".exe", ".bin"]


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

    for dirName, subdirList, fileList in os.walk(directories.MOD_DIR, followlinks=True):
        for fname in fileList:
            if fname.endswith('.tests.ps1'):
                # This is done because PowerSploit contains tests that we
                # don't want
                continue
            _, ext = os.path.splitext(fname)
            if ext.lower() not in EXTENSIONS:
                continue
            path = os.path.join(dirName, fname)
            module = import_file(path)
            if module:
                result.append(module)

    enumerate_modules(_modules=result)

    global modules
    modules = result


def import_file(path):
    with open(path, "br") as f:
        buffer = f.read(2048)
        file_type = magic.from_buffer(buffer)
        mime = magic.from_buffer(buffer, mime=True)
        fname = os.path.basename(path)
        mod_type = get_module_type(fname, file_type, mime)
        if not mod_type:
            return
    module = Module(
        path.replace(directories.MOD_DIR, ''),
        path,
        mod_type,
        file_type,
    )
    log.debug("Imported module (%s): %s" % (path, mod_type))
    return module


def enumerate_modules(_modules=modules):
    for i, m in enumerate(_modules):
        m.n = i


class Module(object):
    """Represents a module
    """

    def __init__(self, name, path, type, file_type):
        self.name = name
        self._path = path
        self.type = type
        self.file_type = file_type
        self.n = -1
        self._code = None

    @property
    def code(self):
        if self._code is None:
            self._code = open(self._path, 'rb').read()
            if self.type == 'ps1':
                self._code = sanitize_ps1(self._code, self.file_type)

        return self._code

    def as_dict(self):
        return {
            "Name": self.name,
            "BaseName": os.path.basename(self.name),
            "N": self.n,
            "Type": self.type,
            "Loaded": "$False",
            "Alias": "$Null",
        }


def find_module_by_path(path):
    for m in modules:
        if m._path == path:
            return m


def on_created(event):
    module = import_file(event.src_path)
    if not module:
        return
    modules.append(module)
    module.n = len(modules) - 1
    log.info("Module added (%d): %s" % (module.n, module.name))


def on_deleted(event):
    m = find_module_by_path(event.src_path)
    if not m:
        return
    log.info("Module deleted: %s" % m.name)
    modules.remove(m)
    enumerate_modules()


def on_modified(event):
    module = import_file(event.src_path)
    if not module:
        return
    log.info("Module modified: %s" % module.name)
    m = find_module_by_path(event.src_path)
    module.n = m.n
    modules[m.n] = module


def on_moved(event):
    m = find_module_by_path(event.src_path)
    log.info("Module renamed: %s" % m.name)
    m._path = event.dest_path
    m.name = m._path.replace(directories.MOD_DIR, '')


def set_up_watchdog():
    """Watch for changed files and updated the modules"""

    patterns = ['*' + e for e in EXTENSIONS]
    ignore_patterns = None
    ignore_directories = False
    case_sensitive = False
    my_event_handler = PatternMatchingEventHandler(
        patterns, ignore_patterns, ignore_directories, case_sensitive
    )

    my_event_handler.on_created = on_created
    my_event_handler.on_deleted = on_deleted
    my_event_handler.on_modified = on_modified
    my_event_handler.on_moved = on_moved

    path = directories.MOD_DIR
    go_recursively = True
    my_observer = Observer()
    my_observer.schedule(my_event_handler, path, recursive=go_recursively)

    watchdog = threading.Thread(target=my_observer.start, daemon=True)
    watchdog.start()
