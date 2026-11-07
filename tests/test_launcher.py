import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cineca_grader_launcher import AgentAuthentication, Connection, run_script


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Replace only the SSH transport; run the actual generated remote shell
        # command in a subprocess, without accessing a real cluster or agent.
        ssh = self.root / "ssh"
        ssh.write_text(
            f"#!{sys.executable}\n"
            "import subprocess, sys\n"
            "sys.exit(subprocess.call(['/bin/sh', '-c', sys.argv[-1]]))\n"
        )
        ssh.chmod(0o700)
        self.env = patch.dict(os.environ, {
            "SSH_AUTH_SOCK": "/test-agent",
            "PATH": f"{self.root}{os.pathsep}{os.environ['PATH']}",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.connection = Connection("testuser")

    def test_waits_for_remote_script_and_returns_its_failure(self):
        script = self.root / "script.sh"
        marker = self.root / "finished"
        script.write_text('sleep 0.05\nprintf done > "$1"\nexit 17\n')
        status = run_script(self.connection, str(script), (str(marker),))
        self.assertEqual(status, 17)
        self.assertEqual(marker.read_text(), "done")

    def test_quotes_paths_working_directory_and_arguments(self):
        directory = self.root / "work ' $(false)"
        directory.mkdir()
        script = directory / "-script ' name.sh"
        script.write_text('printf "%s\\n" "$@" > result\n')
        args = ("", "two words", "$(touch injected)", "'; touch injected; #", "--flag")
        self.assertEqual(run_script(self.connection, script.name, args, cwd=str(directory)), 0)
        self.assertEqual((directory / "result").read_text().splitlines(), list(args))
        self.assertFalse((directory / "injected").exists())

    def test_missing_working_directory_prevents_execution(self):
        script = self.root / "script.sh"
        marker = self.root / "executed"
        script.write_text('touch "$1"\n')
        self.assertNotEqual(run_script(self.connection, str(script), (str(marker),), cwd=str(self.root / "absent")), 0)
        self.assertFalse(marker.exists())

    def test_streams_local_bash_script_with_arguments(self):
        script = self.root / "local.sh"
        marker = self.root / "result"
        script.write_text('printf "%s" "$2" > "$1"\nexit 23\n')
        status = run_script(self.connection, str(script), (str(marker), "hello ' world"), local=True)
        self.assertEqual(status, 23)
        self.assertEqual(marker.read_text(), "hello ' world")

    def test_slurm_waits_and_propagates_status(self):
        sbatch = self.root / "sbatch"
        sbatch.write_text('#!/bin/sh\n[ "$1" = "--wait" ] || exit 99\nshift\nexec bash "$@"\n')
        sbatch.chmod(0o700)
        script = self.root / "batch.sh"
        marker = self.root / "completed"
        script.write_text('sleep 0.05\nprintf finished > "$1"\nexit 19\n')
        self.assertEqual(run_script(self.connection, str(script), (str(marker),), slurm=True), 19)
        self.assertEqual(marker.read_text(), "finished")

    def test_agent_is_required(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "SSH_AUTH_SOCK"):
                AgentAuthentication().prepare()

    def test_authentication_prepares_before_connecting(self):
        events = []

        class Authentication:
            def prepare(self):
                events.append("authenticate")

        def transport(*args, **kwargs):
            events.append("connect")
            return subprocess.CompletedProcess(args, 0)

        with patch("cineca_grader_launcher.launcher.subprocess.run", side_effect=transport):
            run_script(self.connection, "job.sh", authentication=Authentication())
        self.assertEqual(events, ["authenticate", "connect"])

    def test_ssh_uses_agent_and_secure_noninteractive_options(self):
        command = self.connection.ssh_command("exec bash -- ./job.sh")
        for option in (
            "BatchMode=yes", "PreferredAuthentications=publickey",
            "StrictHostKeyChecking=yes", "ForwardAgent=no", "IdentityAgent=/test-agent",
        ):
            self.assertIn(option, command)

    def test_invalid_inputs_fail_before_connecting(self):
        with self.assertRaises(ValueError):
            Connection("user", "-oProxyCommand=bad")
        with self.assertRaises(ValueError):
            Connection("user", port=0)
        with self.assertRaises(ValueError):
            run_script(self.connection, "script.sh", local=True, slurm=True)

    def test_cli_propagates_status_and_script_flags(self):
        script = self.root / "script.sh"
        script.write_text('printf "%s\\n" "$@"\nexit 42\n')
        result = subprocess.run(
            [sys.executable, "-m", "cineca_grader_launcher", "--user", "testuser", str(script), "--host", "literal"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 42)
        self.assertEqual(result.stdout, "--host\nliteral\n")


if __name__ == "__main__":
    unittest.main()
