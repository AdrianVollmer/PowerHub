import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def save_file(file):
    upload_dir = os.path.join(BASE_DIR, "upload")
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    filename = os.path.join(upload_dir, str(file.filename))
    if os.path.isfile(filename):
        count = 1
        while os.path.isfile("%s.%d" % (filename, count)):
            count += 1
        filename += ".%d" % count
    file.save(filename)
