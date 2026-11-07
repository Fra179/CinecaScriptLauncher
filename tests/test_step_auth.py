import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

from cineca_grader_launcher import Credentials, StepAuthentication
from cineca_grader_launcher.step_auth import read_env
from test_auth import URL, SECRET


class StepAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.marker = self.root / 'callback'
        self.executable = self.root / 'step-cli with spaces'
        environment = patch.dict(os.environ, {'SSH_AUTH_SOCK': '/test-agent'})
        environment.start()
        self.addCleanup(environment.stop)
        self.credentials = Credentials('email@example.com', 'password-secret', SECRET)

    def script(self, body):
        self.executable.write_text(f'#!{sys.executable}\n' + body)
        self.executable.chmod(0o700)
        return StepAuthentication(self.credentials, str(self.executable), 3)

    def test_starts_configured_executable_logs_in_and_waits_for_step(self):
        args = self.root / 'args'
        finished = self.root / 'finished'
        authentication = self.script(
            'import os, sys, time\n'
            'assert os.environ["STEP_OPEN_BROWSER"] == "0"\n'
            'assert "STEP_CONSOLE" not in os.environ\n'
            'assert "CINECA_PASSWORD" not in os.environ\n'
            'assert "CINECA_TOTP_SECRET" not in os.environ\n'
            f'open({str(args)!r}, "w").write(repr(sys.argv[1:]))\n'
            f'print({URL!r}, flush=True)\n'
            f'while not os.path.exists({str(self.marker)!r}): time.sleep(0.01)\n'
            f'open({str(finished)!r}, "w").write("done")\n'
        )
        def callback(url, credentials, timeout):
            self.assertEqual(url, URL)
            self.assertEqual(credentials, self.credentials)
            self.assertGreater(timeout, 0)
            self.marker.touch()
        with patch.dict(os.environ, {'CINECA_PASSWORD': 'do-not-inherit', 'CINECA_TOTP_SECRET': SECRET, 'STEP_CONSOLE': 'true'}):
            with patch('cineca_grader_launcher.step_auth.login', side_effect=callback) as login:
                authentication.prepare()
        login.assert_called_once()
        self.assertEqual(args.read_text(), repr(['ssh', 'login', '--provisioner', 'cineca-hpc', self.credentials.email]))
        self.assertEqual(finished.read_text(), 'done')

    def test_reuses_certificate_when_step_succeeds_without_url(self):
        authentication = self.script('print("Already loaded")\n')
        with patch('cineca_grader_launcher.step_auth.login') as login:
            authentication.prepare()
            login.assert_not_called()

    def test_cli_loads_default_env_without_prompting(self):
        marker = self.root / 'started'
        self.script(f'open({str(marker)!r}, "w").write("started")\n')
        (self.root / '.env').write_text(
            f'CINECA_STEP_EXECUTABLE="{self.executable}"\n'
            f'CINECA_EMAIL={self.credentials.email}\n'
            f'CINECA_PASSWORD={self.credentials.password}\n'
            f'CINECA_TOTP_SECRET={SECRET}\n'
        )
        result = subprocess.run(
            [sys.executable, '-c', 'from cineca_grader_launcher.login_cli import main; main()'],
            cwd=self.root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())
        self.assertIn('Step login completed', result.stdout)
        self.assertNotIn(self.credentials.password, result.stdout + result.stderr)

    def test_step_failure_does_not_echo_output(self):
        authentication = self.script('import sys\nprint("secret-token")\nsys.exit(7)\n')
        with self.assertRaisesRegex(ValueError, 'exit 7') as error:
            authentication.prepare()
        self.assertNotIn('secret-token', str(error.exception))

    def test_timeout_and_login_failure_terminate_step(self):
        for fail_login in (False, True):
            with self.subTest(fail_login=fail_login):
                pid = self.root / 'pid'
                authentication = self.script(
                    'import os, time\n'
                    f'open({str(pid)!r}, "w").write(str(os.getpid()))\n'
                    f'print({URL!r}, flush=True)\n'
                    'time.sleep(60)\n'
                )
                authentication = StepAuthentication(self.credentials, authentication.executable, 0.5)
                with patch('cineca_grader_launcher.step_auth.login', side_effect=ValueError('rejected') if fail_login else None):
                    with self.assertRaisesRegex(ValueError, 'rejected' if fail_login else 'timed out'):
                        authentication.prepare()
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid.read_text()), 0)

    def test_reads_literal_dotenv_and_environment_overrides(self):
        env_file = self.root / '.env'
        env_file.write_text(
            '# login\nexport CINECA_EMAIL=file@example.com\n'
            'CINECA_PASSWORD=\'literal $VALUE `command` # password\' # comment\n'
            f'CINECA_TOTP_SECRET="{SECRET}"\n'
            'CINECA_STEP_EXECUTABLE="/some path/step-cli"\n'
            'CINECA_AUTH_TIMEOUT=45 # seconds\n'
        )
        with patch.dict(os.environ, {'CINECA_EMAIL': 'override@example.com'}, clear=True):
            authentication = StepAuthentication.from_env_file(env_file)
        self.assertEqual(authentication.credentials.email, 'override@example.com')
        self.assertEqual(authentication.credentials.password, 'literal $VALUE `command` # password')
        self.assertEqual(authentication.executable, '/some path/step-cli')
        self.assertEqual(authentication.timeout, 45)
        self.assertNotIn(SECRET, repr(authentication))
        self.assertNotIn('literal $VALUE', repr(authentication))

    def test_bad_configuration_fails_before_starting_step(self):
        env_file = self.root / '.env'
        env_file.write_text('CINECA_EMAIL=email@example.com\n')
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, 'CINECA_PASSWORD'):
                StepAuthentication.from_env_file(env_file)
        env_file.write_text('CINECA_PASSWORD="unterminated\n')
        with self.assertRaisesRegex(ValueError, 'line 1'):
            read_env(env_file)
        with patch('cineca_grader_launcher.step_auth.subprocess.Popen') as process:
            with self.assertRaises(ValueError):
                StepAuthentication(self.credentials, timeout=float('nan')).prepare()
            process.assert_not_called()
