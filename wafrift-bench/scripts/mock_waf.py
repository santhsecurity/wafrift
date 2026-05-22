#!/usr/bin/env python3
"""Mock WAF emulating a ModSec-class block pattern.

Listens on 127.0.0.1:18099. Returns:
- 403 Forbidden (Apache + ModSecurity banner) on any request whose
  raw bytes contain a known attack-shaped substring (SQL/XSS/cmd/path/
  SSTI patterns from the OWASP CRS).
- 200 OK (gunicorn banner) otherwise.

Used by the wafrift pentest-dogfood pass when no docker is available.
Drops 1 line per request to stderr so the operator can see what hit.
"""
import http.server
import socketserver
import sys
import re
import urllib.parse

ATTACK_PATTERNS = [
    re.compile(rb"' ?OR ?1=1", re.I),
    re.compile(rb"\bUNION\s+SELECT\b", re.I),
    re.compile(rb"<script[^>]*>", re.I),
    re.compile(rb"javascript:", re.I),
    re.compile(rb"onerror=", re.I),
    re.compile(rb"\.\./|\.\.%2f|\.\.\\", re.I),
    re.compile(rb";\s*(rm|cat|nc|curl|wget|bash|sh)\b", re.I),
    re.compile(rb"\$\{[^}]*jndi:", re.I),
    re.compile(rb"\{\{[^}]*\}\}"),
    re.compile(rb"<!ENTITY", re.I),
    re.compile(rb"\$_GET|\$_POST|eval\(", re.I),
]

class MockWAFHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-waf] %s %s\n" % (self.command, self.path))
        sys.stderr.flush()

    def _classify(self, body):
        # ModSec-class WAFs decode the input pipeline (urlDecodeUni,
        # htmlEntityDecode, etc.) before pattern matching. Mock the
        # FIRST stage (single URL-decode) so the mock catches the same
        # surface a real CRS PL1 catches: payload bytes after one URL
        # decode pass. Without this the mock would let `%27+OR+1%3D1`
        # straight through which is dishonest emulation.
        decoded_path = urllib.parse.unquote_plus(self.path)
        try:
            decoded_body = urllib.parse.unquote_plus(body.decode("latin-1", errors="replace"))
        except Exception:
            decoded_body = body.decode("latin-1", errors="replace")
        blob = (
            self.path + " " + decoded_path + " " + str(self.headers) + " "
            + body.decode("latin-1", errors="replace") + " " + decoded_body
        ).encode("latin-1", errors="replace")
        for pat in ATTACK_PATTERNS:
            if pat.search(blob):
                return True, pat.pattern
        return False, None

    def _respond(self, body=b""):
        blocked, pattern = self._classify(body)
        if blocked:
            page = b"<html><body><h1>403 Forbidden</h1><p>Mod_Security: Access denied. (ID 949110)</p></body></html>\n"
            self.send_response(403)
            self.send_header("Server", "Apache/2.4.41")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("X-Mock-WAF-Match", pattern.decode("latin-1", errors="replace")[:80])
            self.end_headers()
            self.wfile.write(page)
        else:
            page = b'{"ok":true,"path":"%s"}' % self.path.encode("utf-8", errors="replace")
            self.send_response(200)
            self.send_header("Server", "gunicorn/19.9.0")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

    def do_GET(self):
        self._respond(b"")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        self._respond(body)

    def do_PUT(self):  self._respond(b"")
    def do_DELETE(self): self._respond(b"")
    def do_PATCH(self): self._respond(b"")
    def do_HEAD(self): self._respond(b"")
    def do_OPTIONS(self): self._respond(b"")

class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
    with ThreadingServer(("127.0.0.1", port), MockWAFHandler) as srv:
        sys.stderr.write(f"[mock-waf] listening on 127.0.0.1:{port}\n")
        sys.stderr.flush()
        srv.serve_forever()
