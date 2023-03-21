import logging
import os
import shutil
import sys
import subprocess
from shlex import split

from test_config import TEST_URI, BACKENDS  # noqa
# test_config must define these variables. they are local to the computer
# you are running this on, so the file is not tracked by git.
# mine looks something like this:
#  TEST_URI = "192.168.11.2"
#  BACKENDS = {
#      "win7": {
#          "psversion": 2,
#          "command": "sshpass -e ssh win7",
#          "copy":  "sshpass -e scp %(src)s win7:%(dst)s",
#          "env": {
#              "SSHPASS": "!pass show win7-test-vm",
#          },
#      },
#      "win10": {
#          "psversion": 5,
#          "command": "ssh win10",
#          "copy":  "scp %(src)s win10:%(dst)s",
#      },
#  }
# `env` is a dict where the keys are either consts or commands. Consts
# must be preceded with `=`, commands with `!`.


sys.argv = ['powerhub', TEST_URI, '--no-auth']
NEW_XDG_DATA_HOME = os.path.join(os.sep, 'tmp', 'powerhub_test')
log = logging.getLogger(__name__)


def init_tests():
    myPath = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(myPath, '..', '..'))

    os.environ["XDG_DATA_HOME"] = NEW_XDG_DATA_HOME
    try:
        shutil.rmtree(NEW_XDG_DATA_HOME)
    except FileNotFoundError:
        pass
    os.makedirs(NEW_XDG_DATA_HOME)


def execute_cmd(backend, cmd, copy=False):
    env = os.environ
    env["PYTHONIOENCODING"] = "utf8"
    for k, v in backend.get('env', {}).items():
        if v.startswith('='):
            env[k] = v[1:]
        elif v.startswith('1'):
            env[k] = subprocess.check_output(
                split(v[1:])
            )[:-1].decode()
        else:
            raise RuntimeError("env values must start with ! or =")

    if copy:
        # cmd must not contain exactly one space
        cmd = backend['copy'] % dict(
            src=cmd.split(" ")[0],
            dst=cmd.split(" ")[1],
        )
        cmd = split(cmd)
    else:
        cmd = split(backend['command']) + [cmd]

    log.info("Running: %s" % " ".join(cmd))
    output = subprocess.run(
        cmd,
        env=env,
        check=False,
        capture_output=True,
    )
    # Can't rely on return code. `ssh win10 xxx` returns 0 if the last
    # command was successful.

    if output.returncode or output.stderr:
        result = output.stderr[:-1].decode()
    else:
        result = output.stdout[:-1].decode()

    return result
