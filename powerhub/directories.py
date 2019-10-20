import os

_HOME = os.path.expanduser('~')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XDG_DATA_HOME = os.environ.get('XDG_DATA_HOME') or \
        os.path.join(_HOME, '.local', 'share', 'powerhub')
UPLOAD_DIR = os.path.join(XDG_DATA_HOME, "upload")
LOOT_DIR = os.path.join(XDG_DATA_HOME, "loot")
MOD_DIR = os.path.join(XDG_DATA_HOME, 'modules')
WEBDAV_DIR = os.path.join(XDG_DATA_HOME, 'webdav')
WEBDAV_RO = os.path.join(XDG_DATA_HOME, 'webdav_ro')
WEBDAV_BLACKHOLE = os.path.join(WEBDAV_DIR, 'blackhole')
WEBDAV_PUBLIC = os.path.join(WEBDAV_DIR, 'public')
SHELL_LOG_DIR = os.path.join(XDG_DATA_HOME, 'shell_logs')
CERT_DIR = os.path.join(XDG_DATA_HOME, 'ssl')


def ensure_dir_exists(dirname):
    """Creates a directory if it doesn't exist already

    """
    if not os.path.exists(dirname):
        os.makedirs(dirname)


directories = [
    UPLOAD_DIR,
    LOOT_DIR,
    XDG_DATA_HOME,
    WEBDAV_DIR,
    MOD_DIR,
    os.path.join(MOD_DIR, 'ps1'),
    os.path.join(MOD_DIR, 'exe'),
    os.path.join(MOD_DIR, 'shellcode'),
    WEBDAV_RO,
    WEBDAV_BLACKHOLE,
    WEBDAV_PUBLIC,
    SHELL_LOG_DIR,
    CERT_DIR,
]

for d in directories:
    ensure_dir_exists(d)

DB_FILENAME = os.path.join(XDG_DATA_HOME, "powerhub_db.sqlite")
