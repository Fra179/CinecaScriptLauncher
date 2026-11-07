"""Use OpenSSH for agent authentication, host verification, and transport."""

from contextlib import ExitStack
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex
import subprocess
from typing import Protocol


class Authentication(Protocol):
    """Preparation seam for future certificate acquisition before connecting."""

    def prepare(self) -> None: ...


class AgentAuthentication:
    """Use credentials already loaded into the caller's SSH agent."""

    def prepare(self) -> None:
        if not os.environ.get("SSH_AUTH_SOCK"):
            raise ValueError(
                "SSH_AUTH_SOCK is unset. Start an SSH agent and load your valid "
                "CINECA key/certificate before running the launcher. "
                "Step login also requires a running SSH agent."
            )


@dataclass(frozen=True)
class Connection:
    username: str
    host: str = "login.leonardo.cineca.it"
    port: int = 22
    connect_timeout: int = 30

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", self.username):
            raise ValueError("Invalid SSH username")
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*", self.host):
            raise ValueError("Invalid SSH hostname or alias")
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        if self.connect_timeout <= 0:
            raise ValueError("Connection timeout must be positive")

    def ssh_command(self, remote_command: str) -> list[str]:
        return [
            "ssh", "-T",
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "ForwardAgent=no",
            "-o", f"IdentityAgent={os.environ.get('SSH_AUTH_SOCK', '')}",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-p", str(self.port),
            "-l", self.username,
            self.host,
            remote_command,
        ]


def run_script(
    connection: Connection,
    script: str,
    args: tuple[str, ...] = (),
    *,
    cwd: str | None = None,
    slurm: bool = False,
    local: bool = False,
    authentication: Authentication | None = None,
) -> int:
    """Block until execution finishes; inherit output and return SSH's status.

    Remote scripts run with Bash, or with sbatch --wait when slurm=True.
    A local Bash script can instead be streamed over stdin with local=True.
    """
    if not script or "\0" in script:
        raise ValueError("Script path must be nonempty and contain no NUL bytes")
    if cwd is not None and (not cwd or "\0" in cwd):
        raise ValueError("Remote working directory must be nonempty and contain no NUL bytes")
    if any("\0" in arg for arg in args):
        raise ValueError("Script arguments cannot contain NUL bytes")
    if local and slurm:
        raise ValueError("--local cannot be combined with --slurm; upload the batch script first")

    if local:
        command = shlex.join(["bash", "-s", "--", *args])
    else:
        # Prefix relative paths so a filename beginning with '-' is never an option.
        path = script if script.startswith("/") else f"./{script}"
        executable = ["sbatch", "--wait"] if slurm else ["bash"]
        command = shlex.join([*executable, "--", path, *args])
    if cwd is not None:
        directory = cwd if cwd.startswith("/") else f"./{cwd}"
        command = f"cd -- {shlex.quote(directory)} && exec {command}"
    else:
        command = f"exec {command}"

    with ExitStack() as stack:
        stdin = stack.enter_context(Path(script).open("rb")) if local else subprocess.DEVNULL
        (authentication if authentication is not None else AgentAuthentication()).prepare()
        result = subprocess.run(connection.ssh_command(command), stdin=stdin, check=False)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode
