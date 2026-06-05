#!/usr/bin/env python3
"""Multi-context reflective origin for EXECUTION benchmarking.

The waf-zoo's default backend is httpbin, which echoes the request as JSON —
so an injected XSS payload can never EXECUTE there regardless of the WAF, and
the bench can only ever measure *bypass*, never *exploitation*. This origin is
the opposite: it is deliberately, obviously XSS-vulnerable so that a payload
which gets PAST the WAF actually runs in a browser, letting the detonation
oracle (`bench-waf --prove-execution`, `exploit --detonate-engine chrome`)
measure the honest bypass-vs-exploit split.

A first generation reflected `q` only into the HTML body + an `innerHTML` sink.
On that single-decode body origin, OWASP CRS blocks every executable markup
vector at every paranoia level, so thousands of *bypasses* reflect **inert** and
0 EXECUTE. That is real — but it only proves CRS beats *one* reflection context.
Real apps expose many. This origin reflects `q` into the contexts that turn a
"WAF bypass" into a working exploit, selected by the `ctx` query parameter:

  * ``body``     (default) — ``<div>{q}</div>`` plus an ``innerHTML`` DOM sink.
                  Auto-firing handlers (``<svg onload>``) and mXSS fire here.
                  Kept byte-identical to gen-1 so prior numbers reproduce.
  * ``attr``     — ``<input value="{q}">`` : double-quote attribute breakout
                  (``"><svg onload=...>`` or ``" autofocus onfocus=...``).
  * ``attr_sq``  — ``<input value='{q}'>`` : single-quote attribute breakout.
  * ``js``       — ``<script>var t="{q}";</script>`` : JS double-quoted-string
                  breakout (``";alert(1);//``). The high-value bridge: a payload
                  with NO angle brackets and NO event-handler attribute — which
                  many WAF rulesets never policed — executes verbatim here.
  * ``js_sq``    — ``<script>var t='{q}';</script>`` : single-quote JS string.
  * ``dd``       — double-decode: the (already URL-decoded) ``q`` is decoded a
                  SECOND time before reflection, modelling an app that decodes
                  twice. A double-percent-encoded ``%253Csvg%2520onload...`` is
                  inert text to the WAF (no ``<``) yet decodes to live markup in
                  the app — the classic encode-to-bypass / decode-to-execute
                  bridge that single-decode origins cannot model.
  * ``uri``      — ``<a href="{q}">`` auto-clicked: ``javascript:`` URI context.
  * ``hpp``      — reflects into the body like ``body``, but the handler joins
                  ALL repeated ``q=`` values (HTTP Parameter Pollution): a
                  payload split into inert fragments across params — each one no
                  WAF signature — reassembles into live markup. A parsing-layer
                  evasion axis with nothing encoded (``exploit --split-param``).

Gen-4 adds the **app-transform** axis (the one that beats CRS at every paranoia
level). The ctx grammar is ``[<transform>.]<render>``: a *transform* decodes the
value before it is reflected into a *render* context. ``b64`` / ``hex`` / ``b32``
/ ``rot13`` are genuinely WAF-opaque — CRS has no transform to reverse them, so
it sees an inert blob while the app decodes live markup that executes. ``zb64``
(base64+zlib URL-state compression), ``b58`` (Bitcoin base58) and ``b64x2`` (a
double-base64 decode chain) generalise the axis beyond base-N: a WAF that models
every base encoding still cannot inflate DEFLATE, decode a bignum alphabet, or
peel a chain. ``dd`` (double-URL), ``jsesc`` (``\\uXXXX``) and ``entity``
(``&#60;``) are NEGATIVE CONTROLS: CRS *does* model those decoders, so they stay
blocked. Transforms compose with every render context: ``ctx=b64.attr``
base64-decodes into an attribute breakout, ``ctx=hex.js`` hex-decodes into a JS
string, etc. Empirically ``<img src=x onerror=alert(1)>`` base64'd passes CRS 4.x
PL1-PL4 (anomaly ~3 of 5) and executes; the same payload raw, or via
``jsesc``/``entity``/``dd``, is 403'd.

DO NOT deploy this anywhere reachable. It exists only behind a WAF in a lab.
"""
import base64
import codecs
import html
import json
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 80


def _b64(value: str) -> str:
    # Tolerant base64: restore stripped padding, accept urlsafe alphabet — what a
    # real `atob()`/library decode would forgive. validate=False so surrounding
    # whitespace is ignored.
    s = value.strip()
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def _hex(value: str) -> str:
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace("\\x", "").replace(" ", "").replace(":", "")
    return bytes.fromhex(s).decode("utf-8", "replace")


def _b32(value: str) -> str:
    s = value.strip().upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s).decode("utf-8", "replace")


def _jsesc(value: str) -> str:
    # Model `JSON.parse`/JS string unescaping of `\uXXXX` / `\xXX` escapes.
    return codecs.decode(value.encode("utf-8", "replace"), "unicode_escape")


def _b64_bytes(value: str) -> bytes:
    # Tolerant base64 → raw bytes (shared by the binary-output transforms).
    s = value.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def _zb64(value: str) -> str:
    # base64 → zlib-inflate: the URL-state-compression idiom (pako / lz-string
    # share-links). The WAF sees a high-entropy blob with no transform to inflate.
    return zlib.decompress(_b64_bytes(value)).decode("utf-8", "replace")


def _zhex(value: str) -> str:
    # hex → zlib-inflate: same compression as zb64 but a PL4-clean [0-9a-f]
    # alphabet (CRS PL4 flags base64's +/=, so zb64 bypasses ~27% vs zhex ~100%).
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return zlib.decompress(bytes.fromhex(s)).decode("utf-8", "replace")


_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(value: str) -> str:
    # Bitcoin base58 decode (base-58 → base-256). Leading `1`s are leading
    # zero bytes. Models a web3/crypto app decoding a base58 identifier.
    s = value.strip()
    zeros = len(s) - len(s.lstrip("1"))
    n = 0
    for ch in s:
        n = n * 58 + _B58_ALPHABET.index(ch.encode())
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return (b"\x00" * zeros + body).decode("utf-8", "replace")


def _b64x2(value: str) -> str:
    # Two base64 layers (a decode chain). After one decode the value is still an
    # opaque base64 blob, so a WAF that peels a single layer gains no signature.
    return _b64(_b64(value))


_B62_ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62(value: str) -> str:
    # Base62 decode (base-62 → base-256), GMP digit order 0-9A-Za-z. Leading `0`s
    # are leading zero bytes. Pure-alphanumeric, so the blob carries zero special
    # characters for a CRS character rule to count — the cleanest PL4 alphabet.
    s = value.strip()
    zeros = len(s) - len(s.lstrip("0"))
    n = 0
    for ch in s:
        n = n * 62 + _B62_ALPHABET.index(ch.encode())
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return (b"\x00" * zeros + body).decode("utf-8", "replace")


def _zrawb64(value: str) -> str:
    # base64 → RAW-inflate (RFC 1951, no zlib header): the `pako.inflateRaw(atob(x))`
    # idiom that dominates JS SPAs. `wbits=-15` selects the headerless stream.
    return zlib.decompress(_b64_bytes(value), -15).decode("utf-8", "replace")


# App-side decoders selected by `ctx`. Each takes the (already URL-decoded)
# value and returns the live string the app would reflect. b64/hex/rot13 are
# genuinely WAF-opaque (CRS has no transform for them); entity/jsesc are
# negative controls (CRS's htmlEntityDecode/jsDecode see through them).
_TRANSFORMS = {
    "b64": _b64,
    "hex": _hex,
    "b32": _b32,
    "rot13": lambda v: codecs.decode(v, "rot13"),
    "jsesc": _jsesc,
    "entity": html.unescape,
    # `dd` = the app URL-decodes a SECOND time (the query layer decoded once).
    "dd": urllib.parse.unquote_plus,
    # Categorically distinct WAF-opaque decoders (not base-N variants): a
    # signature WAF that models every base encoding still can't inflate DEFLATE,
    # decode a bignum alphabet, or peel a decode chain.
    "zb64": _zb64,
    "zhex": _zhex,
    "b58": _b58,
    "b64x2": _b64x2,
    "b62": _b62,
    "zrawb64": _zrawb64,
}

# Reflection contexts this origin understands. The default (`body`) is kept
# byte-for-byte identical to the first-generation origin so historical numbers
# reproduce exactly; the rest are the contexts that weaponise a WAF bypass.
#
# The TRANSFORM contexts (`b64`, `hex`, `rot13`, `jsesc`, `entity`) model an
# application that runs an attacker-controllable value through a decoder BEFORE
# reflecting it into the executable body/innerHTML sink — `atob()` in a SPA, a
# base64/hex token field rendered after decode, a templating layer that
# HTML-unescapes, `JSON.parse` on a `\uXXXX`-escaped string. The WAF sees an
# OPAQUE encoded blob carrying no XSS signature; the app decodes it to live
# markup and it executes. Unlike the percent-encodings CRS normalises with its
# own transforms, an arbitrary app-side decoder is something the WAF cannot
# reverse without knowing the app — the "transform CRS can't model" frontier.
# (`entity`/`jsesc` are deliberate NEGATIVE controls: CRS *does* apply
# htmlEntityDecode / jsDecode when inspecting, so it CAN see through them — they
# should stay blocked, isolating which decoders are genuinely WAF-opaque.)
#
# ctx GRAMMAR — `[<transform>.]<render>`. A transform decodes the value; a
# render context places the decoded value in executable markup. They compose:
# `ctx=b64.attr` base64-decodes THEN reflects into a double-quoted attribute, so
# an attribute-breakout vector executes through an app that base64-decodes a
# value into an attribute. A bare render context (`attr`) applies no transform;
# a bare transform (`b64`) renders into `body` (back-compat with gen-2 numbers).
# `hpp` renders identically to `body`, but the request handler reassembles the
# value from ALL repeated `q=` parameters (HTTP Parameter Pollution): an app that
# joins duplicate values sees one live markup string, while the WAF inspected
# only the individual inert fragments. The split point is chosen so no single
# fragment is a WAF signature — a parsing-layer evasion axis, nothing encoded.
# `title`/`textarea` (RCDATA) and `style` (RAWTEXT) are additional real
# reflection sinks: the `</title>`/`</textarea>`/`</style>` breakout catalog
# re-enters markup and executes there, multiplying the number of contexts a
# decoded/reassembled payload can execute in. (An iframe-`srcdoc` sink was tried
# and dropped: its XSS fires in the child document, which the detonation oracle's
# top-frame alert hook cannot observe — an unmeasurable sink is excluded.)
RENDER_CONTEXTS = ("body", "attr", "attr_sq", "js", "js_sq", "uri", "hpp",
                   "title", "textarea", "style")
TRANSFORM_NAMES = tuple(_TRANSFORMS.keys())
# Legacy flat list — every single-token context that remains valid on its own.
CONTEXTS = RENDER_CONTEXTS + TRANSFORM_NAMES


def _parse_ctx(ctx: str):
    """Parse a ctx token into ``(transform_or_None, render_context)``.

    Returns ``(None, "body")`` for anything unrecognised so a malformed ctx is
    inert rather than an error.
    """
    if "." in ctx:
        t, _, r = ctx.partition(".")
        if t in _TRANSFORMS and r in RENDER_CONTEXTS:
            return t, r
        return None, "body"
    if ctx in RENDER_CONTEXTS:
        return None, ctx
    if ctx in _TRANSFORMS:
        return ctx, "body"
    return None, "body"


def _doc(inner: str, raw_value: str) -> bytes:
    """Wrap a context-specific ``inner`` fragment in the standard lab page."""
    body = (
        "<!doctype html><html><head><title>reflect-origin</title></head><body>\n"
        f"{inner}\n"
        f"<!-- echo: {html.escape(raw_value)} -->\n"
        "</body></html>\n"
    )
    return body.encode("utf-8", "replace")


def render(raw_value: str, ctx: str) -> bytes:
    """Reflect ``raw_value`` (already transform-decoded) into ctx's RENDER part.

    Every context reflects the value UNescaped — that is the deliberate
    vulnerability. The render context decides the surrounding markup, which is
    what decides whether a given WAF bypass actually executes.
    """
    _t, r = _parse_ctx(ctx)
    if r == "attr":
        inner = f'<input id="f" type="text" value="{raw_value}">'
    elif r == "attr_sq":
        inner = f"<input id=\"f\" type=\"text\" value='{raw_value}'>"
    elif r == "js":
        inner = f'<script>\n  var t = "{raw_value}";\n  window.__t = t;\n</script>'
    elif r == "js_sq":
        inner = f"<script>\n  var t = '{raw_value}';\n  window.__t = t;\n</script>"
    elif r == "uri":
        # `javascript:` URI sink. A plain anchor only fires on a real click, so
        # the page synthetically clicks it — exactly what a SPA router or a
        # "click to continue" flow does with attacker-controlled href.
        inner = (
            f'<a id="lnk" href="{raw_value}">go</a>\n'
            "<script>try{document.getElementById('lnk').click();}catch(e){}</script>"
        )
    elif r == "title":
        # RCDATA context: only `</title>` ends it, so a `</title><svg onload=...>`
        # breakout re-enters markup and executes.
        inner = f"<title>{raw_value}</title><p>t</p>"
    elif r == "textarea":
        # RCDATA context: `</textarea>` breakout re-enters markup.
        inner = f'<textarea id="f">{raw_value}</textarea>'
    elif r == "style":
        # RAWTEXT context: `</style>` breakout re-enters markup.
        inner = f"<style>#x{{color:red}}{raw_value}</style>"
    else:
        # `body`: reflect into body text AND an innerHTML DOM sink. json.dumps
        # gives a safe JS string literal for the sink assignment without
        # hand-rolled escaping — the XSS is the body reflection plus the sink.
        js_literal = json.dumps(raw_value)
        inner = (
            f'<div id="body-ctx">{raw_value}</div>\n'
            '<div id="sink"></div>\n'
            "<script>\n"
            f"  try {{ document.getElementById('sink').innerHTML = {js_literal}; }} catch (e) {{}}\n"
            "</script>"
        )
    return _doc(inner, raw_value)


class Handler(BaseHTTPRequestHandler):
    server_version = "reflect-origin/2.0"

    def _params(self, query: str) -> dict:
        return urllib.parse.parse_qs(query, keep_blank_values=True)

    def _ctx(self, params: dict) -> str:
        # Accept any ctx that parses to a valid (transform?, render) pair —
        # including composite `b64.attr`. Anything else collapses to `body`.
        ctx = params.get("ctx", ["body"])[-1]
        t, r = _parse_ctx(ctx)
        if t is None and r == "body" and ctx not in ("body",):
            return "body"  # unrecognised token → inert body
        return ctx

    @staticmethod
    def _decode_for(value: str, ctx: str) -> str:
        # Apply the ctx's TRANSFORM part (if any): the app runs an
        # attacker-controllable decoder over the value before reflecting it.
        # Best-effort — a value that does not decode cleanly reflects empty
        # (clearly inert), never crashes the origin. Each models a real, common
        # app behaviour (atob / hex / base32 / rot13 / double-URL-decode).
        t, _r = _parse_ctx(ctx)
        if t is not None:
            try:
                return _TRANSFORMS[t](value)
            except Exception:
                return ""
        return value

    def _send_html(self, value: str, ctx: str) -> None:
        out = render(self._decode_for(value, ctx), ctx)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    @staticmethod
    def _value_for(params: dict, ctx: str) -> str:
        # `hpp` render: the app concatenates ALL repeated `q=` values (HTTP
        # Parameter Pollution reassembly) with no separator, so a payload split
        # across params — each fragment inert to the WAF — becomes live markup.
        # Every other context takes the last value (standard last-wins).
        _t, r = _parse_ctx(ctx)
        qs = params.get("q", [""])
        return "".join(qs) if r == "hpp" else qs[-1]

    def do_GET(self):
        params = self._params(urllib.parse.urlparse(self.path).query)
        ctx = self._ctx(params)
        self._send_html(self._value_for(params, ctx), ctx)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        query_params = self._params(urllib.parse.urlparse(self.path).query)
        ctx = self._ctx(query_params)
        value = ""
        if "application/x-www-form-urlencoded" in ctype:
            value = self._params(raw.decode("utf-8", "replace")).get("q", [""])[-1]
        elif raw:
            # raw_body mode: the whole body IS the payload.
            value = raw.decode("utf-8", "replace")
        if not value:
            value = query_params.get("q", [""])[-1]
        self._send_html(value, ctx)

    def log_message(self, *_args):
        pass  # quiet


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
