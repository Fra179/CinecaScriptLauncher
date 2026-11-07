"""Complete a live step-cli Keycloak browser session without storing secrets."""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
from html.parser import HTMLParser
import http.cookiejar
import math
import struct
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, Request, build_opener


SSO_ORIGIN = "https://sso.hpc.cineca.it"
AUTH_PATH = "/realms/CINECA-HPC/protocol/openid-connect/auth"


@dataclass(frozen=True)
class Credentials:
    email: str
    password: str = field(repr=False)
    totp_secret: str = field(repr=False)


def totp(secret: str, timestamp: float | None = None) -> str:
    """Generate the default Keycloak six-digit SHA-1 / 30-second TOTP."""
    normalized = "".join(secret.split()).upper().rstrip("=")
    try:
        key = base64.b32decode(normalized + "=" * (-len(normalized) % 8))
    except ValueError:
        raise ValueError("TOTP master key must be a Base32 secret") from None
    if not key:
        raise ValueError("TOTP master key is empty")
    counter = int(time.time() if timestamp is None else timestamp) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1_000_000:06d}"


def _sso_url(url: str) -> bool:
    parsed = urlsplit(url)
    return (parsed.scheme == "https" and parsed.netloc == "sso.hpc.cineca.it"
            and parsed.path.startswith("/realms/CINECA-HPC/"))


class _Forms(HTMLParser):
    def __init__(self, html: str):
        super().__init__()
        self.forms = []
        self.current = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""),
                            "method": attrs.get("method", "get").lower(),
                            "fields": {}, "names": set()}
            self.forms.append(self.current)
        elif tag == "input" and self.current is not None:
            name = attrs.get("name")
            if name and "disabled" not in attrs:
                self.current["names"].add(name)
                if attrs.get("type", "text").lower() == "hidden":
                    self.current["fields"][name] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def login(auth_url: str, credentials: Credentials, *, timeout: float = 30) -> None:
    """Submit credentials and OTP, then deliver the code to a live step callback.

    The URL must come from a currently waiting step-cli process on this machine.
    No token exchange is attempted here: step owns the PKCE verifier and state.
    """
    parsed = urlsplit(auth_url)
    query = parse_qs(parsed.query)
    def single(name):
        values = query.get(name, [])
        if len(values) != 1 or not values[0]:
            raise ValueError("Invalid step-cli authorization URL")
        return values[0]

    if not _sso_url(auth_url) or parsed.path != AUTH_PATH or parsed.fragment:
        raise ValueError("Expected the CINECA HPC authorization URL")
    if single("client_id") != "step-ca" or single("response_type") != "code":
        raise ValueError("Expected a step-ca authorization-code session")
    if single("code_challenge_method") != "S256":
        raise ValueError("Expected a PKCE S256 session")
    single("code_challenge")
    state, callback = single("state"), single("redirect_uri")
    destination = urlsplit(callback)
    if (destination.scheme != "http" or destination.hostname not in ("127.0.0.1", "localhost", "::1")
            or destination.username or destination.password or not destination.port
            or destination.path not in ("", "/") or destination.query or destination.fragment):
        raise ValueError("Expected a loopback step-cli callback with an explicit port")
    if not credentials.email or not credentials.password:
        raise ValueError("Email and password are required")
    totp(credentials.totp_secret)  # Validate before submitting a password.
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Authentication timeout must be positive")

    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
    deadline = time.monotonic() + timeout
    def request(url, data=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("CINECA authentication timed out")
        try:
            return opener.open(Request(url, data=data), timeout=remaining)
        except HTTPError as exc:
            if exc.code in (301, 302, 303, 307, 308):
                return exc
            exc.close()
            raise ValueError("CINECA authentication returned an HTTP error") from None

    url, data = auth_url, None
    password_sent = otp_sent = False
    try:
        for _ in range(12):
            with request(url, data) as response:
                if response.code in (301, 302, 303, 307, 308):
                    target = urljoin(url, response.headers.get("Location", ""))
                    result = urlsplit(target)
                    if (result.scheme, result.netloc, result.path or "/") == (
                            destination.scheme, destination.netloc, destination.path or "/"):
                        params = parse_qs(result.query)
                        if (params.get("state") != [state] or len(params.get("code", [])) != 1
                                or not params["code"][0] or "error" in params or result.fragment):
                            raise ValueError("Invalid or unsuccessful CINECA callback")
                        # This request contains only the authorization code and state.
                        with request(target) as completed:
                            if completed.code != 200:
                                raise ValueError("step-cli did not accept the callback")
                        return
                    if not _sso_url(target):
                        raise ValueError("CINECA redirected outside the expected login service")
                    if response.code not in (307, 308):
                        data = None
                    url = target
                    continue
                html = response.read(1_000_001)
                if len(html) > 1_000_000:
                    raise ValueError("CINECA returned an oversized login page")
            forms = _Forms(html.decode("utf-8")).forms
            form = next((f for f in forms if {"username", "password"} <= f["names"]), None)
            if form is not None and not password_sent:
                fields = form["fields"] | {"username": credentials.email, "password": credentials.password}
                password_sent = True
            else:
                form = next((f for f in forms if "otp" in f["names"]), None)
                if form is None or otp_sent or not password_sent:
                    raise ValueError("CINECA login rejected or requires an unsupported interactive step")
                fields = form["fields"] | {"otp": totp(credentials.totp_secret)}
                otp_sent = True
            target = urljoin(url, form["action"])
            if form["method"] != "post" or not _sso_url(target):
                raise ValueError("Unexpected CINECA login form destination")
            url, data = target, urlencode(fields).encode()
        raise ValueError("CINECA authentication exceeded the page limit")
    except (URLError, OSError, UnicodeError):
        raise ValueError("CINECA authentication connection failed; check the network and live step-cli session") from None
