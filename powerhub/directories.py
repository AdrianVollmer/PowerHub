import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, "upload")
MOD_DIR = os.path.join(BASE_DIR, 'modules')
WEBDAV_DIR = os.path.join(BASE_DIR, 'webdav')
WEBDAV_RO = os.path.join(WEBDAV_DIR, 'ro')
WEBDAV_BLACKHOLE = os.path.join(WEBDAV_DIR, 'blackhole')
WEBDAV_PUBLIC = os.path.join(WEBDAV_DIR, 'public')
BLACKHOLE_DIR = os.path.join(BASE_DIR, 'blackhole')


def ensure_dir_exists(dirname):
    """Creates a directory if it doesn't exist already

    """
    if not os.path.exists(dirname):
        os.makedirs(dirname)


directories = [
    UPLOAD_DIR,
    WEBDAV_DIR,
    MOD_DIR,
    BLACKHOLE_DIR,
    os.path.join(MOD_DIR, 'ps1'),
    os.path.join(MOD_DIR, 'exe'),
    os.path.join(MOD_DIR, 'shellcode'),
    WEBDAV_RO,
    WEBDAV_BLACKHOLE,
    WEBDAV_PUBLIC,
    BLACKHOLE_DIR,
]

for d in directories:
    ensure_dir_exists(d)

#  os.chmod(WEBDAV_RO, 0o555)
#  os.chmod(WEBDAV_BLACKHOLE, 0o755)
#  os.chmod(WEBDAV_PUBLIC, 0o755)
