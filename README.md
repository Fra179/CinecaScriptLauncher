# CINECA grader launcher

Run a Bash script over SSH on Leonardo and wait for it to finish. Uses the system
OpenSSH client and the key/certificate already available in your running SSH agent.
No Python runtime dependencies are required. Python 3.14+ and `ssh` must be installed.

Install with `uv sync`, then run `uv run cineca-grader-launcher --help`.
Alternatively, use `pip install .` and run `cineca-grader-launcher` directly.

## Authentication

Install and bootstrap Smallstep following the official access instructions below,
and start your SSH agent so `SSH_AUTH_SOCK` is set. Copy `.env.example` to `.env`
and fill in your credentials:

```dotenv
CINECA_STEP_EXECUTABLE=step-cli
CINECA_EMAIL=your-email@example.com
CINECA_PASSWORD='your-password'
CINECA_TOTP_SECRET='your-base32-master-key'
CINECA_AUTH_TIMEOUT=120
```

`CINECA_STEP_EXECUTABLE` defaults to `step`; use `step-cli` or an absolute executable
path if needed. This is one executable path, without flags or shell commands.
Protect `.env` with `chmod 600 .env`; `.env` and `.env.*` are ignored by Git,
except for `.env.example`. Never put real credentials in the example file.

Run authentication on its own:

```sh
uv run cineca-login
# Or choose a different configuration file:
uv run cineca-login --env-file /path/to/cineca.env
```

Or authenticate and then run your remote script in one command:

```sh
uv run cineca-grader-launcher --env-file .env --user YOUR_USERNAME ./grade.sh
```

The program starts `step ssh login --provisioner cineca-hpc YOUR_EMAIL` using the
configured executable, disables browser launch through `STEP_OPEN_BROWSER=0`,
reads the fresh authorization URL, submits your password and TOTP, and delivers
the code to Step's local callback. It waits for Step to exit successfully before
connecting over SSH. Step owns the PKCE verifier and certificate issuance, and
can reuse a valid certificate already in the agent. Startup, login and issuance
share `CINECA_AUTH_TIMEOUT` seconds (default 120). Failed or interrupted login
terminates the Step process; credentials are never retried automatically.

The file supports literal `KEY=value` lines, optional `export`, single/double
quotes and comments. It does not execute commands, expand variables, interpret
backslash escapes or support multiline values. Existing environment variables
have precedence over file values. Passwords and TOTP secrets are never passed
as process arguments or inherited by Step. Captured Step output is not logged
because it can include authorization URLs and tokens.

The TOTP master key is the Base32 authenticator setup secret, not a current
six-digit code or a recovery code. Keep your system clock synchronized. The
supported login flow uses password plus six-digit SHA-1/30-second TOTP; first-time
setup, password changes and recovery challenges require browser interaction.
The program requires a bootstrapped CA configuration and a running SSH agent.

For an already running Step session, the manual mode remains available:

```sh
uv run cineca-login --email 'YOUR_EMAIL' --auth-url 'FRESH_AUTHORIZATION_URL'
```

This mode prompts for secrets with hidden input and requires Step's callback
listener on the same machine. Old URLs cannot be reused after their session ends.

CINECA uses temporary SSH certificates for 2FA access, rather than a password
retrieved by `step-cli`: see the [official access instructions](https://docs.hpc.cineca.it/general/access.html).
The default host is `login.leonardo.cineca.it`, as documented in the
[Leonardo guide](https://docs.hpc.cineca.it/hpc/leonardo.html).

Host keys must already be trusted in your OpenSSH `known_hosts`. Verify and trust
the host through your normal SSH setup before using this noninteractive launcher.
SSH configuration is respected (including proxy settings); password prompts and
agent forwarding are disabled, and the current `SSH_AUTH_SOCK` selects the agent.

## Usage

Run a script already on Leonardo (paths are relative to the remote login directory
unless `--cwd` is supplied). Remote Bash scripts need not be executable:

```sh
uv run cineca-grader-launcher --user YOUR_USERNAME --cwd /remote/project ./grade.sh input.json
```

For compute workloads, submit an existing Slurm batch script and wait through
queueing and execution:

```sh
uv run cineca-grader-launcher --user YOUR_USERNAME --slurm --cwd /remote/project ./grade.sbatch input.json
```

Put account, partition, time and resource requests in the script's `#SBATCH`
directives. This mode uses [`sbatch --wait`](https://slurm.schedmd.com/sbatch.html)
and returns its exit status. Slurm prints the job ID; job output goes to the files
selected by the script, or Slurm's default `slurm-%j.out`, rather than streaming
through this CLI. Direct mode streams stdout/stderr and returns Bash's exit status.
A script that backgrounds work or submits jobs itself must wait for that work;
direct mode only waits for the script process.

To execute a local Bash script without uploading it first:

```sh
uv run cineca-grader-launcher --user YOUR_USERNAME --local --cwd /remote/project ./check.sh 'argument with spaces'
```

`--local` streams the script through stdin; supporting files are not uploaded and
stdin is occupied by the script. It cannot be combined with `--slurm`; upload batch
scripts and their inputs separately. Direct mode runs on a login node, so use it
for lightweight setup/checks and use Slurm for compute workloads.

Place all launcher options before the script path. Arguments after the script path
are passed literally, without remote shell expansion. Use absolute remote paths
instead of `~` or environment variables. Additional options: `--host` (also accepts
an SSH config alias), `--port`, and `--connect-timeout SECONDS` (default 30; this
limits connection setup, not job runtime).

The launcher does not retry after a broken connection, resume waiting, or cancel
remote jobs automatically. After interruption or an SSH failure, check the job's
state before resubmitting; use `scancel JOB_ID` to cancel a submitted job. SSH
transport/authentication errors return 255 (also a possible script exit code),
local configuration errors return 2, and Ctrl-C returns 130.

## Python API

```python
from cineca_grader_launcher import Connection, run_script

status = run_script(
    Connection(username="YOUR_USERNAME"),
    "grade.sbatch",
    ("input.json",),
    cwd="/remote/project",
    slurm=True,
)
```

`run_script` accepts an optional authentication object exposing `prepare()`, called
before opening SSH. By default it uses `AgentAuthentication`. To authenticate within the API call, pass
`authentication=StepAuthentication.from_env_file(".env")` (import
`StepAuthentication` from `cineca_grader_launcher`).

## Development

```sh
uv run python -m unittest discover -s tests -v
```

Tests replace SSH with a local transport to verify shell quoting, completion,
exit statuses, local script streaming, and the Slurm wait invocation. They do not
connect to Leonardo. Authentication tests simulate password, OTP and callback
responses, check a published TOTP test vector, and reject untrusted destinations
and mismatched callback state. Process tests use a fake Step executable to check
configuration, URL handling, waiting, reuse, failures, secret isolation and cleanup.
The live CINECA password form was inspected, but
the OTP page and certificate issuance require credentials and a waiting Smallstep
session for end-to-end verification.
