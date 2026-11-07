"""Command-line interface for the synchronous SSH launcher."""

import argparse
import sys

from .launcher import Connection, run_script
from .step_auth import StepAuthentication


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a script on Leonardo using your SSH agent and wait for completion.",
        epilog="Put launcher options before SCRIPT; everything after SCRIPT is passed to the script.",
    )
    parser.add_argument("--user", required=True, help="CINECA SSH username")
    parser.add_argument("--host", default="login.leonardo.cineca.it", help="SSH hostname or config alias")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--connect-timeout", type=int, default=30, metavar="SECONDS")
    parser.add_argument("--cwd", help="Remote working directory (defaults to the login directory)")
    parser.add_argument("--slurm", action="store_true", help="Submit a remote batch script with sbatch --wait")
    parser.add_argument("--local", action="store_true", help="Stream a local Bash script over SSH instead")
    parser.add_argument("--env-file", help="Start Step and authenticate using this .env file before running the script")
    parser.add_argument("script", help="Remote script path, or local path with --local")
    parser.add_argument("script_args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    try:
        status = run_script(
            Connection(options.user, options.host, options.port, options.connect_timeout),
            options.script,
            tuple(options.script_args),
            cwd=options.cwd,
            slurm=options.slurm,
            local=options.local,
            authentication=StepAuthentication.from_env_file(options.env_file) if options.env_file else None,
        )
    except (OSError, ValueError) as exc:
        print(f"cineca-grader-launcher: {exc}", file=sys.stderr)
        status = 2
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Remote execution may continue; a submitted Slurm job "
            "is not cancelled automatically (use scancel JOB_ID).",
            file=sys.stderr,
        )
        status = 130
    if status == 255:
        print(
            "SSH failed or the remote script returned 255. Check the SSH output above, "
            "your agent certificate, and the host's known_hosts entry. "
            "If a job was submitted, check its state before retrying.",
            file=sys.stderr,
        )
    raise SystemExit(status)
