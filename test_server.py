#!/usr/bin/env python3
"""
Intentionally vulnerable CSRF test server for XSRFProbe.

Each endpoint demonstrates a different CSRF weakness that XSRFProbe should detect.
Run with: python test_server.py
Then scan with: python -m xsrfprobe.xsrfprobe -u http://127.0.0.1:5000/ --crawl --no-verify --no-analysis -v
"""

import uuid
import hashlib
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode

HOST = "127.0.0.1"
PORT = 5000

GLOBAL_TOKEN_POOL = {}
SESSION_STORE = {}


def _new_session_id():
    return secrets.token_hex(16)


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body>
<h1>{title}</h1>
<nav>
  <a href="/">Home</a> |
  <a href="/no-token">No Token</a> |
  <a href="/login">Login CSRF</a> |
  <a href="/weak-token">Weak Token</a> |
  <a href="/global-token">Global Token (T4)</a> |
  <a href="/double-submit">Double Submit (T6)</a> |
  <a href="/no-referer-check">No Referer Check</a> |
  <a href="/content-type-bypass">Content-Type Bypass (M4)</a> |
  <a href="/protected">Protected Form</a>
</nav>
<hr/>
{body}
</body>
</html>"""


class VulnerableHandler(BaseHTTPRequestHandler):

    def _send_html(self, html: str, code: int = 200, extra_headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        sid = self._get_or_create_session()
        self.send_header("Set-Cookie", f"session_id={sid}; Path=/")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(html.encode())

    def _get_or_create_session(self) -> str:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session_id="):
                sid = part.split("=", 1)[1]
                if sid in SESSION_STORE:
                    return sid
        sid = _new_session_id()
        SESSION_STORE[sid] = {"user": "victim"}
        return sid

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode() if length else ""
        return dict(p.split("=", 1) for p in raw.split("&") if "=" in p)

    # ── GET router ───────────────────────────────────────────────

    def do_GET(self):
        path = urlparse(self.path).path
        routes = {
            "/": self._index,
            "/no-token": self._no_token_get,
            "/login": self._login_get,
            "/weak-token": self._weak_token_get,
            "/global-token": self._global_token_get,
            "/double-submit": self._double_submit_get,
            "/no-referer-check": self._no_referer_check_get,
            "/content-type-bypass": self._content_type_bypass_get,
            "/protected": self._protected_get,
        }
        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_html(_page("404", "<p>Not found</p>"), 404)

    # ── POST router ──────────────────────────────────────────────

    def do_POST(self):
        path = urlparse(self.path).path
        routes = {
            "/no-token": self._no_token_post,
            "/login": self._login_post,
            "/weak-token": self._weak_token_post,
            "/global-token": self._global_token_post,
            "/double-submit": self._double_submit_post,
            "/no-referer-check": self._no_referer_check_post,
            "/content-type-bypass": self._content_type_bypass_post,
            "/protected": self._protected_post,
        }
        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_html(_page("404", "<p>Not found</p>"), 404)

    def do_HEAD(self):
        self.do_GET()

    # ── Index ────────────────────────────────────────────────────

    def _index(self):
        body = """
        <h2>CSRF Vulnerable Test Endpoints</h2>
        <ul>
          <li><a href="/no-token">No Token</a> – Form with no CSRF token at all</li>
          <li><a href="/login">Login CSRF</a> – Login form without CSRF protection</li>
          <li><a href="/weak-token">Weak Token</a> – Token present but not validated (T2/T3/T7)</li>
          <li><a href="/global-token">Global Token (T4)</a> – Token not tied to session</li>
          <li><a href="/double-submit">Double Submit (T6)</a> – Cookie == body token, no server-side binding</li>
          <li><a href="/no-referer-check">No Referer Check</a> – No Referer/Origin validation</li>
          <li><a href="/content-type-bypass">Content-Type Bypass (M4)</a> – Accepts any Content-Type</li>
          <li><a href="/protected">Protected Form</a> – Properly CSRF-protected (control case)</li>
        </ul>
        """
        self._send_html(_page("CSRF Test Server", body))

    # ── 1. No token at all ───────────────────────────────────────

    def _no_token_get(self):
        body = """
        <h2>Transfer Funds (No Token)</h2>
        <form method="POST" action="/no-token">
          <label>Amount: <input type="text" name="amount" value="100"/></label><br/>
          <label>To: <input type="text" name="recipient" value="attacker"/></label><br/>
          <input type="submit" value="Transfer"/>
        </form>
        """
        self._send_html(_page("No Token Form", body))

    def _no_token_post(self):
        params = self._read_body()
        body = f"<p>Transferred ${params.get('amount', '?')} to {params.get('recipient', '?')}. Success!</p>"
        self._send_html(_page("Transfer Complete", body))

    # ── 2. Login CSRF (O1) ──────────────────────────────────────

    def _login_get(self):
        body = """
        <h2>Login (No CSRF Token)</h2>
        <form method="POST" action="/login">
          <label>Username: <input type="text" name="username"/></label><br/>
          <label>Password: <input type="password" name="password"/></label><br/>
          <input type="submit" value="Login"/>
        </form>
        """
        self._send_html(_page("Login", body))

    def _login_post(self):
        params = self._read_body()
        body = f"<p>Welcome, {params.get('username', 'user')}!</p>"
        self._send_html(_page("Logged In", body))

    # ── 3. Weak token – present but never validated (T2/T3/T7) ──

    def _weak_token_get(self):
        token = secrets.token_hex(16)
        body = f"""
        <h2>Change Email (Weak Token)</h2>
        <form method="POST" action="/weak-token">
          <input type="hidden" name="csrf_token" value="{token}"/>
          <label>New Email: <input type="email" name="email"/></label><br/>
          <input type="submit" value="Update"/>
        </form>
        """
        self._send_html(_page("Weak Token", body))

    def _weak_token_post(self):
        params = self._read_body()
        body = f"<p>Email changed to {params.get('email', '?')}. Success!</p>"
        self._send_html(_page("Email Updated", body))

    # ── 4. Global token pool – not tied to session (T4) ─────────

    def _global_token_get(self):
        token = secrets.token_hex(16)
        GLOBAL_TOKEN_POOL[token] = True
        body = f"""
        <h2>Change Password (Global Token)</h2>
        <form method="POST" action="/global-token">
          <input type="hidden" name="csrf_token" value="{token}"/>
          <label>New Password: <input type="password" name="new_password"/></label><br/>
          <input type="submit" value="Change"/>
        </form>
        """
        self._send_html(_page("Global Token (T4)", body))

    def _global_token_post(self):
        params = self._read_body()
        token = params.get("csrf_token", "")
        if token in GLOBAL_TOKEN_POOL:
            body = "<p>Password changed! Success!</p>"
            self._send_html(_page("Password Changed", body))
        else:
            self._send_html(_page("Error", "<p>Invalid token.</p>"), 403)

    # ── 5. Double-submit cookie (T6) ────────────────────────────

    def _double_submit_get(self):
        token = secrets.token_hex(16)
        body = f"""
        <h2>Update Profile (Double Submit)</h2>
        <form method="POST" action="/double-submit">
          <input type="hidden" name="csrf_token" value="{token}"/>
          <label>Display Name: <input type="text" name="display_name"/></label><br/>
          <input type="submit" value="Update"/>
        </form>
        """
        extra = {"Set-Cookie": f"csrf_token={token}; Path=/"}
        self._send_html(_page("Double Submit (T6)", body), extra_headers=extra)

    def _double_submit_post(self):
        params = self._read_body()
        body_token = params.get("csrf_token", "")

        cookie = self.headers.get("Cookie", "")
        cookie_token = ""
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("csrf_token="):
                cookie_token = part.split("=", 1)[1]

        if body_token and body_token == cookie_token:
            body = f"<p>Profile updated: {params.get('display_name', '?')}. Success!</p>"
            self._send_html(_page("Profile Updated", body))
        else:
            self._send_html(_page("Error", "<p>Token mismatch.</p>"), 403)

    # ── 6. No Referer/Origin check ──────────────────────────────

    def _no_referer_check_get(self):
        body = """
        <h2>Delete Account (No Referer Check)</h2>
        <form method="POST" action="/no-referer-check">
          <label>Confirm: <input type="text" name="confirm" value="yes"/></label><br/>
          <input type="submit" value="Delete My Account"/>
        </form>
        """
        self._send_html(_page("No Referer Check", body))

    def _no_referer_check_post(self):
        body = "<p>Account deleted! (No referer/origin was checked.)</p>"
        self._send_html(_page("Account Deleted", body))

    # ── 7. Content-Type bypass (M4) ─────────────────────────────

    def _content_type_bypass_get(self):
        body = """
        <h2>Add Admin (Content-Type Bypass)</h2>
        <form method="POST" action="/content-type-bypass">
          <label>Admin Email: <input type="email" name="admin_email"/></label><br/>
          <input type="submit" value="Add Admin"/>
        </form>
        """
        self._send_html(_page("Content-Type Bypass (M4)", body))

    def _content_type_bypass_post(self):
        params = self._read_body()
        body = f"<p>Admin {params.get('admin_email', '?')} added! Success!</p>"
        self._send_html(_page("Admin Added", body))

    # ── 8. Properly protected (control) ─────────────────────────

    def _protected_get(self):
        sid = self._get_or_create_session()
        token = secrets.token_hex(16)
        SESSION_STORE[sid]["csrf_token"] = token
        body = f"""
        <h2>Update Settings (Protected)</h2>
        <form method="POST" action="/protected">
          <input type="hidden" name="csrf_token" value="{token}"/>
          <label>Theme: <input type="text" name="theme" value="dark"/></label><br/>
          <input type="submit" value="Save"/>
        </form>
        """
        self._send_html(_page("Protected Form", body))

    def _protected_post(self):
        params = self._read_body()
        sid = self._get_or_create_session()
        session = SESSION_STORE.get(sid, {})
        expected = session.get("csrf_token", "")

        if not params.get("csrf_token") or params["csrf_token"] != expected:
            self._send_html(_page("Error", "<p>Invalid CSRF token.</p>"), 403)
            return

        session.pop("csrf_token", None)
        body = f"<p>Settings saved: theme={params.get('theme', '?')}.</p>"
        self._send_html(_page("Settings Saved", body))

    def log_message(self, format, *args):
        pass


def main():
    server = HTTPServer((HOST, PORT), VulnerableHandler)
    print(f"[*] CSRF test server running on http://{HOST}:{PORT}/")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
