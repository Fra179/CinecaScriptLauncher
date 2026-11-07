"""Authenticate from a .env file, or prompt to complete an existing session."""

import argparse
import getpass
import sys

from .auth import Credentials, login
from .step_auth import StepAuthentication


def main() -> None:
    parser = argparse.ArgumentParser(description="Start Step and authenticate to CINECA using a .env file.")
    parser.add_argument("--env-file", default=".env", help="Login configuration file (default: .env)")
    parser.add_argument("--auth-url", help="Complete an existing Step session instead of starting Step")
    parser.add_argument("--email", help="CINECA email or username, for manual --auth-url mode")
    parser.add_argument("--timeout", type=float, default=30, help="Network timeout in seconds for manual --auth-url mode")
    options = parser.parse_args()
    try:
        if options.auth_url:
            if not options.email:
                parser.error("--email is required with --auth-url")
            login(options.auth_url, Credentials(
                options.email, getpass.getpass("CINECA password: "),
                getpass.getpass("TOTP master key (Base32): "),
            ), timeout=options.timeout)
        else:
            StepAuthentication.from_env_file(options.env_file).prepare()
    except (OSError, ValueError) as exc:
        print(f"cineca-login: {exc}", file=sys.stderr)
        raise SystemExit(2)
    except (KeyboardInterrupt, EOFError):
        print("\nAuthentication cancelled.", file=sys.stderr)
        raise SystemExit(130)
    print("SSO callback delivered. Check step-cli for certificate issuance." if options.auth_url
          else "Step login completed; SSH credentials are available in the agent.")
