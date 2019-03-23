import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(BASE_DIR, "upload")
MOD_DIR = os.path.join(BASE_DIR, 'modules')
WEBDAV_DIR = os.path.join(BASE_DIR, 'webdav')
BLACKHOLE_DIR = os.path.join(BASE_DIR, 'blackhole')


def ensure_dir_exists(dirname):
    """Creates a directory if it doesn't exist already

    """
    if not os.path.exists(dirname):
        os.makedirs(dirname)


ensure_dir_exists(UPLOAD_DIR)
ensure_dir_exists(WEBDAV_DIR)
ensure_dir_exists(MOD_DIR)
ensure_dir_exists(BLACKHOLE_DIR)
ensure_dir_exists(os.path.join(MOD_DIR, 'ps1'))
ensure_dir_exists(os.path.join(MOD_DIR, 'exe'))
ensure_dir_exists(os.path.join(MOD_DIR, 'shellcode'))
ensure_dir_exists(os.path.join(WEBDAV_DIR, 'ro'))
ensure_dir_exists(os.path.join(WEBDAV_DIR, 'public'))
ensure_dir_exists(os.path.join(WEBDAV_DIR, 'blackhole'))
