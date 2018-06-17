import os
from powerhub.settings import BASE_DIR


def save_file(file):
    filename = os.path.join(BASE_DIR, "upload", str(file))
    if os.path.isfile(filename):
        count = 1
        while os.path.isfile("%s.%d" % (filename, count)):
            count += 1
        filename += ".%d" % count
    with open(filename, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
