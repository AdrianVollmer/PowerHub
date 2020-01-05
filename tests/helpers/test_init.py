import os
import shutil
import sys


TEST_URI = 'foobar'


def init_tests():
    myPath = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, myPath + '/../../')

    NEW_XDG_DATA_HOME = os.path.join(os.sep, 'tmp', 'ph_test')
    os.environ["XDG_DATA_HOME"] = NEW_XDG_DATA_HOME
    try:
        shutil.rmtree(NEW_XDG_DATA_HOME)
    except FileNotFoundError:
        pass
    os.makedirs(NEW_XDG_DATA_HOME)
