"""Browser sign-in shared by both platforms: the OAuth authorization code flow with PKCE (S256)
and a state check. A one-shot listener on this computer receives the browser's redirect, or,
with --no-browser on Google, the person pastes the redirected address. Nothing is saved to
disk: the caller swaps the code for a token that lives in memory for the run."""

import base64
import getpass
import hashlib
import secrets
import select
import socket
import socketserver
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer


class SignInError(Exception):
    pass


def pkce_pair():
    """Return (verifier, challenge) for PKCE with S256."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorize_url(base, client_id, redirect, scope, state, challenge, extra=None):
    params = {"client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": scope,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": state}
    params.update(extra or {})
    return base + ("&" if "?" in base else "?") + urllib.parse.urlencode(params)


def read_redirect(params, state):
    """params: the redirect's query values. Return the code, or raise SignInError."""
    if params.get("state") != state:
        raise SignInError("the answer does not belong to this sign-in (state mismatch). Start again")
    if params.get("error"):
        raise SignInError(params.get("error_description") or params["error"])
    if not params.get("code"):
        raise SignInError("no sign-in code came back")
    return params["code"]


def _query(text):
    return {k: v[0] for k, v in urllib.parse.parse_qs(text, keep_blank_values=False).items()}


def parse_pasted(text, state):
    """Read a code from an address pasted from the browser bar (or just its query part)."""
    text = (text or "").strip().strip("'\"<>").strip()
    if "?" in text:
        text = text.split("?", 1)[1]
    return read_redirect(_query(text.split("#", 1)[0]), state)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        q = _query(urllib.parse.urlsplit(self.path).query)
        if q.get("state") != self.server.expected_state:
            self.send_response(404)  # a favicon request or a stray visitor
            self.end_headers()
            return
        self.server.answer.update(q)
        ok = "code" in q and "error" not in q
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<p>Signed in. You can close this tab and go back to the terminal.</p>" if ok else
                         b"<p>Sign-in did not complete. Go back to the terminal for what to do next.</p>")

    def log_message(self, *args):
        pass


class _Server(HTTPServer):
    def server_bind(self):  # skip HTTPServer's reverse DNS lookup of the address
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "localhost", self.server_address[1]


class _Server6(_Server):
    address_family = socket.AF_INET6


class Loopback:
    """Listen on 127.0.0.1 and, where the system has it, ::1 on the same port, because a
    browser may resolve 'localhost' to either. Only answers that carry the right state count."""

    def __init__(self, state):
        self.answer = {}
        self.servers = [_Server(("127.0.0.1", 0), _Handler)]
        self.port = self.servers[0].server_port
        try:
            self.servers.append(_Server6(("::1", self.port), _Handler))
        except OSError:
            pass
        for s in self.servers:
            s.expected_state, s.answer, s.timeout = state, self.answer, 1

    def wait(self, timeout):
        deadline = time.time() + timeout
        try:
            while not self.answer and time.time() < deadline:
                ready, _, _ = select.select(self.servers, [], [], 1)
                for s in ready:
                    s.handle_request()
        finally:
            self.close()
        return dict(self.answer)

    def close(self):
        for s in self.servers:
            s.server_close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def browser_code(auth_base, client_id, scope, host="127.0.0.1", paste=False, extra=None, timeout=300,
                 opener=webbrowser.open, reader=getpass.getpass, out=print, before_wait=""):
    """Run the browser part of the sign-in. Return (code, redirect_uri, verifier).
    host is what goes in the redirect address: '127.0.0.1' for Google, 'localhost' for Microsoft."""
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    listener = None if paste else Loopback(state)
    try:
        redirect = f"http://{host}:{free_port() if paste else listener.port}"
        url = authorize_url(auth_base, client_id, redirect, scope, state, challenge, extra)
        if paste:
            out(f"Open this address in a browser where you can sign in:\n\n{url}\n")
            out(f"After you approve, the browser tries to open an address starting with {redirect} "
                "and shows an error such as 'site cannot be reached'. That is expected. Copy the whole "
                "address from the address bar and paste it here.")
            return parse_pasted(reader("Address (not shown as you paste, press Enter when done): "), state), \
                redirect, verifier
        out(f"If no browser window opens, paste this address into a browser:\n\n{url}\n")
        if before_wait:
            out(before_wait)
        opener(url)
        answer = listener.wait(timeout)
        if not answer:
            raise SignInError("no answer from the browser in time")
        return read_redirect(answer, state), redirect, verifier
    finally:
        if listener:
            listener.close()
