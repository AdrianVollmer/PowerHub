import os
from datetime import datetime
from operator import itemgetter

from powerhub.env import powerhub_app as ph_app

from powerhub.directories import UPLOAD_DIR
from powerhub.tools import decrypt_aes


def save_file(file, dir=UPLOAD_DIR, encrypted=False):
    """Save a file to the upload directory and return the filename

    If it already exists, append a counter.
    """
    filename = os.path.join(dir, os.path.basename(file.filename))
    if os.path.exists(filename):
        count = 1
        while os.path.isfile("%s.%d" % (filename, count)):
            count += 1
        filename += ".%d" % count
    if encrypted:
        data = file.read()
        data = decrypt_aes(data, ph_app.key)
        with open(filename, 'bw') as f:
            f.write(data)
    else:
        file.save(filename)
    return filename


def get_filelist():
    """Return a list of files in the upload directory"""
    onlyfiles = [f for f in os.listdir(UPLOAD_DIR)
                 if os.path.isfile(os.path.join(UPLOAD_DIR, f))]
    result = [{
                "name": f,
                "size": os.path.getsize(os.path.join(UPLOAD_DIR, f)),
                "date": datetime.fromtimestamp(os.path.getmtime(
                            os.path.join(UPLOAD_DIR, f)
                            )).strftime('%Y-%m-%d %H:%M:%S'),
            } for f in onlyfiles]
    result = sorted(result, key=itemgetter('name'))
    return result
