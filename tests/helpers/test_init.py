import os
import shutil
import sys
from subprocess import check_output
from shlex import split

from test_config import TEST_URI, TEST_COMMANDS  # noqa
# test_config must define these variables. they are local to the computer
# you are running this on, so the file is not tracked by git.
# mine looks something like this:
#  TEST_URI = "192.168.11.2"
#  TEST_COMMANDS = [
#      'ssh win10 \'"%(POWERSHELL_ESCAPED_QUOTES)s"\'',
#      'wmiexec.py -hashes :681d3xxxxxxxxxxxxxxxxxxxxxxxxxxx '
#      + 'Administrator@192.168.11.3 %(BASH)s',
#  ]


sys.argv = ['./powerhub.py', TEST_URI, '--no-auth']
NEW_XDG_DATA_HOME = os.path.join(os.sep, 'tmp', 'ph_test')


def init_tests():
    myPath = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, myPath + '/../../')

    os.environ["XDG_DATA_HOME"] = NEW_XDG_DATA_HOME
    try:
        shutil.rmtree(NEW_XDG_DATA_HOME)
    except FileNotFoundError:
        pass
    os.makedirs(NEW_XDG_DATA_HOME)


def execute_cmd(cmd):
    env = os.environ
    env["PYTHONIOENCODING"] = "utf8"
    return check_output(
        split(cmd),
        env=env,
    )[:-1].decode()
