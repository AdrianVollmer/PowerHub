import collections
import os


DirList = collections.namedtuple(
    'DirList',
    [
        'BASE_DIR',
        'CERT_DIR',
        'MOD_DIR',
        'STATIC_DIR',
        'UPLOAD_DIR',
        'WEBDAV_BLACKHOLE',
        'WEBDAV_DIR',
        'WEBDAV_PRIVATE',
        'WEBDAV_PUBLIC',
        'WEBDAV_RO',
        'XDG_DATA_HOME',
        'DB_FILENAME',
    ],
)
directories = None


def ensure_dir_exists(dirname):
    """Creates a directory if it doesn't exist already

    """
    if not os.path.exists(dirname):
        os.makedirs(dirname)


def init_directories(workspace_dir, create_missing=False):

    _HOME = os.path.expanduser('~')
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    XDG_DATA_HOME = os.path.join(
        os.environ.get('XDG_DATA_HOME') or os.path.join(_HOME, '.local', 'share'),
        'powerhub',
    )

    WORKSPACE_DIR = workspace_dir or os.path.join(XDG_DATA_HOME, 'workspace')
    WORKSPACE_DIR = os.path.abspath(WORKSPACE_DIR)

    UPLOAD_DIR = os.path.join(WORKSPACE_DIR, "upload")
    STATIC_DIR = os.path.join(XDG_DATA_HOME, 'static')
    WEBDAV_DIR = os.path.join(WORKSPACE_DIR, 'webdav')
    WEBDAV_RO = os.path.join(WORKSPACE_DIR, 'webdav_ro')
    WEBDAV_BLACKHOLE = os.path.join(WEBDAV_DIR, 'blackhole')
    WEBDAV_PUBLIC = os.path.join(WEBDAV_DIR, 'public')
    WEBDAV_PRIVATE = os.path.join(WORKSPACE_DIR, 'webdav_private')

    MOD_DIR = os.path.join(XDG_DATA_HOME, 'modules')
    CERT_DIR = os.path.join(XDG_DATA_HOME, 'ssl')

    _directories = [
        BASE_DIR,
        CERT_DIR,
        MOD_DIR,
        STATIC_DIR,
        UPLOAD_DIR,
        WEBDAV_BLACKHOLE,
        WEBDAV_DIR,
        WEBDAV_PRIVATE,
        WEBDAV_PUBLIC,
        WEBDAV_RO,
        XDG_DATA_HOME,
        # order is important here, must be same as above
    ]

    if create_missing:
        for d in _directories:
            ensure_dir_exists(d)

    DB_FILENAME = os.path.join(WORKSPACE_DIR, "powerhub_db.sqlite")
    DB_FILENAME = os.path.abspath(DB_FILENAME)
    _directories.append(DB_FILENAME)

    global directories
    directories = DirList(*_directories)
