import os

from powerhub.env import powerhub_app as ph_app


_HOME = os.path.expanduser('~')
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XDG_DATA_HOME = os.path.join(
    os.environ.get('XDG_DATA_HOME') or os.path.join(_HOME, '.local', 'share'),
    'powerhub',
)
WORKSPACE_DIR = ph_app.args.WORKSPACE_DIR or XDG_DATA_HOME

UPLOAD_DIR = os.path.join(WORKSPACE_DIR, "upload")
LOOT_DIR = os.path.join(WORKSPACE_DIR, "loot")
STATIC_DIR = os.path.join(WORKSPACE_DIR, 'static')
WEBDAV_DIR = os.path.join(WORKSPACE_DIR, 'webdav')
WEBDAV_RO = os.path.join(WORKSPACE_DIR, 'webdav_ro')
WEBDAV_BLACKHOLE = os.path.join(WEBDAV_DIR, 'blackhole')
WEBDAV_PUBLIC = os.path.join(WEBDAV_DIR, 'public')

MOD_DIR = os.path.join(XDG_DATA_HOME, 'modules')
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
    STATIC_DIR,
    os.path.join(MOD_DIR, 'ps1'),
    os.path.join(MOD_DIR, 'exe'),
    os.path.join(MOD_DIR, 'shellcode'),
    WEBDAV_RO,
    WEBDAV_BLACKHOLE,
    WEBDAV_PUBLIC,
    CERT_DIR,
]

for d in directories:
    ensure_dir_exists(d)

DB_FILENAME = os.path.join(WORKSPACE_DIR, "powerhub_db.sqlite")
