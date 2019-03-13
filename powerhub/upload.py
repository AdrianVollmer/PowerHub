import os
from datetime import datetime
from operator import itemgetter
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
upload_dir = os.path.join(BASE_DIR, "upload")

if not os.path.exists(upload_dir):
    os.makedirs(upload_dir)


def save_file(file):
    filename = os.path.join(upload_dir, str(file.filename))
    if os.path.isfile(filename):
        count = 1
        while os.path.isfile("%s.%d" % (filename, count)):
            count += 1
        filename += ".%d" % count
    file.save(filename)


def get_filelist():
    onlyfiles = [f for f in os.listdir(upload_dir)
                 if os.path.isfile(os.path.join(upload_dir, f))]
    result = [{
                "name": f,
                "size": os.path.getsize(os.path.join(upload_dir, f)),
                "date": datetime.fromtimestamp(os.path.getmtime(
                            os.path.join(upload_dir, f)
                            )).strftime('%Y-%m-%d %H:%M:%S'),
            } for f in onlyfiles]
    result = sorted(result, key=itemgetter('name'))
    return result
