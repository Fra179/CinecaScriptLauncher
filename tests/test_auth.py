import io
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode
from unittest.mock import patch

from cineca_grader_launcher.auth import Credentials, login, totp


ORIGIN = 'https://sso.hpc.cineca.it'
CALLBACK = 'http://127.0.0.1:10000'
URL = ORIGIN + '/realms/CINECA-HPC/protocol/openid-connect/auth?' + urlencode({
    'client_id': 'step-ca', 'response_type': 'code', 'code_challenge_method': 'S256',
    'code_challenge': 'challenge', 'state': 'expected-state', 'redirect_uri': CALLBACK,
})
SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
CREDS = Credentials('user@example.com', 'test-password', SECRET)
PASSWORD = '<form method="post" action="/realms/CINECA-HPC/login-actions/authenticate?a=1&amp;b=2"><input name="username"><input name="password"><input type="hidden" name="credentialId" value="hidden-value"></form>'
OTP = '<form method="post" action="/realms/CINECA-HPC/login-actions/authenticate?otp=1"><input name="otp"></form>'


class Response(io.BytesIO):
    code = 200


class Session:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return Response(response.encode())


def redirect(target, code=302):
    return HTTPError(ORIGIN, code, 'redirect', {'Location': target}, io.BytesIO())


class AuthenticationTests(unittest.TestCase):
    def test_totp_rfc6238_vector(self):
        self.assertEqual(totp(SECRET, 59), '287082')
        self.assertEqual(totp(' '.join(SECRET.lower()), 59), '287082')
        with self.assertRaises(ValueError):
            totp('invalid!')
        self.assertNotIn(CREDS.password, repr(CREDS))
        self.assertNotIn(SECRET, repr(CREDS))

    def test_password_otp_and_callback_with_hidden_fields(self):
        session = Session([PASSWORD, OTP, redirect(CALLBACK + '?code=authorization-code&state=expected-state'), 'Success'])
        with patch('cineca_grader_launcher.auth.build_opener', return_value=session):
            login(URL, CREDS)
        requests = session.requests
        self.assertEqual(len(requests), 4)
        self.assertEqual(parse_qs(requests[1].data.decode()), {
            'username': [CREDS.email], 'password': [CREDS.password], 'credentialId': ['hidden-value'],
        })
        self.assertEqual(requests[1].full_url, ORIGIN + '/realms/CINECA-HPC/login-actions/authenticate?a=1&b=2')
        self.assertEqual(list(parse_qs(requests[2].data.decode())), ['otp'])
        self.assertIsNone(requests[3].data)
        self.assertNotIn(SECRET.encode(), b''.join(r.data or b'' for r in requests))

    def test_rejected_credentials_are_not_retried(self):
        session = Session([PASSWORD, PASSWORD])
        with patch('cineca_grader_launcher.auth.build_opener', return_value=session):
            with self.assertRaisesRegex(ValueError, 'rejected'):
                login(URL, CREDS)
        self.assertEqual(len(session.requests), 2)

    def test_rejects_secret_exfiltration_and_invalid_state(self):
        cases = [
            ['<form method="post" action="https://evil.example/"><input name="username"><input name="password"></form>'],
            [redirect('https://evil.example/')],
            [redirect(CALLBACK + '?code=secret-code&state=wrong')],
            [redirect(CALLBACK + '?error=access_denied&state=expected-state')],
        ]
        for responses in cases:
            with self.subTest(responses=responses):
                session = Session(responses)
                with patch('cineca_grader_launcher.auth.build_opener', return_value=session):
                    with self.assertRaises(ValueError):
                        login(URL, CREDS)
                self.assertEqual(len(session.requests), 1)

    def test_rejects_untrusted_authorization_url_before_network(self):
        with patch('cineca_grader_launcher.auth.build_opener') as opener:
            for url in [URL.replace(ORIGIN, 'https://evil.example'), URL.replace('127.0.0.1', 'evil.example'), URL + '&state=duplicate']:
                with self.assertRaises(ValueError):
                    login(url, CREDS)
            opener.assert_not_called()

    def test_network_errors_do_not_expose_sensitive_url(self):
        session = Session([URLError('secret-code')])
        with patch('cineca_grader_launcher.auth.build_opener', return_value=session):
            with self.assertRaises(ValueError) as error:
                login(URL, CREDS)
        self.assertNotIn('secret-code', str(error.exception))

    def test_callback_must_be_accepted_without_redirect(self):
        session = Session([redirect(CALLBACK + '?code=authorization-code&state=expected-state'), redirect('https://evil.example/')])
        with patch('cineca_grader_launcher.auth.build_opener', return_value=session):
            with self.assertRaisesRegex(ValueError, 'did not accept'):
                login(URL, CREDS)
        self.assertEqual(len(session.requests), 2)
