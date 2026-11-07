"""Load local login configuration and manage a browserless Smallstep process."""

from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

from .auth import AUTH_PATH, SSO_ORIGIN, Credentials, login, totp
from .launcher import AgentAuthentication


SECRET_NAMES = ('CINECA_PASSWORD', 'CINECA_TOTP_SECRET')


def read_env(path: str | Path) -> dict[str, str]:
    """Read literal KEY=value entries, optionally quoted; never execute or expand."""
    values = {}
    for number, line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        key, separator, value = line.partition('=')
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            raise ValueError(f'Invalid .env assignment at line {number}')
        if value.startswith(('"', "'")):
            end = value.find(value[0], 1)
            if end < 0 or (value[end + 1:].strip() and not value[end + 1:].lstrip().startswith('#')):
                raise ValueError(f'Invalid .env quoted value at line {number}')
            value = value[1:end]
        else:
            value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
        values[key] = value
    return values


@dataclass(frozen=True)
class StepAuthentication:
    credentials: Credentials = field(repr=False)
    executable: str = 'step'
    timeout: float = 120

    @classmethod
    def from_env_file(cls, path: str | Path = '.env') -> 'StepAuthentication':
        values = read_env(path) | dict(os.environ)
        required = ('CINECA_EMAIL', *SECRET_NAMES)
        if any(not values.get(key) for key in required):
            raise ValueError('Set CINECA_EMAIL, CINECA_PASSWORD and CINECA_TOTP_SECRET in the .env file or environment')
        return cls(Credentials(*(values[key] for key in required)),
                   values.get('CINECA_STEP_EXECUTABLE', 'step'),
                   float(values.get('CINECA_AUTH_TIMEOUT', '120')))

    def prepare(self) -> None:
        AgentAuthentication().prepare()
        if not self.executable or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError('Step executable must be nonempty and authentication timeout must be positive')
        if not self.credentials.email or not self.credentials.password:
            raise ValueError('CINECA email and password are required')
        totp(self.credentials.totp_secret)
        environment = {k: v for k, v in os.environ.items() if k not in SECRET_NAMES}
        # Supported by Smallstep's loopback OAuth flow. Console mode would use
        # a different grant type and is intentionally not selected.
        environment['STEP_OPEN_BROWSER'] = '0'
        environment.pop('STEP_CONSOLE', None)
        deadline = time.monotonic() + self.timeout
        command = [self.executable, 'ssh', 'login', '--provisioner', 'cineca-hpc', self.credentials.email]
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       env=environment)
        except OSError:
            raise ValueError('Cannot start Step; check CINECA_STEP_EXECUTABLE') from None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                pending = b''
                authenticated = False
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('Step authentication timed out')
                    if not selector.select(min(remaining, 0.1)):
                        continue
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        selector.unregister(process.stdout)
                        break
                    pending += chunk
                    if len(pending) > 65536:
                        raise ValueError('Step output exceeded the line limit')
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        match = re.search(re.escape(SSO_ORIGIN + AUTH_PATH).encode() + rb'\?[^\s\x1b]+', line)
                        if match and not authenticated:
                            login(match[0].decode('utf-8'), self.credentials,
                                  timeout=max(0.001, deadline - time.monotonic()))
                            authenticated = True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Step authentication timed out')
                try:
                    status = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    raise ValueError('Step authentication timed out') from None
                if status:
                    # Step output can contain tokens and authorization URLs.
                    raise ValueError(f'Step login failed (exit {status}); check CA bootstrap, SSH agent and credentials')
                # A zero exit without a URL means Step reused an existing certificate.
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
