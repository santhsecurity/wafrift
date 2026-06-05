#!/usr/bin/env python3
"""Flatten the wafrift XSS corpus TOMLs into a newline-delimited payload file
for `wafrift exploit --seed-payloads`. One payload per line; deduplicated,
order-stable. Run where the NFS tree (and the corpus) is reachable.
"""
import glob
import os
import sys

try:
    import tomllib
except ModuleNotFoundError:  # py<3.11
    import tomli as tomllib  # type: ignore


def main():
    corpus_dir = sys.argv[1] if len(sys.argv) > 1 else "../../../wafrift-bench/corpus/xss"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "corpus_xss.txt"
    seen, payloads = set(), []
    files = sorted(glob.glob(os.path.join(corpus_dir, "*.toml")))
    for f in files:
        with open(f, "rb") as fh:
            data = tomllib.load(fh)
        for case in data.get("case", []):
            p = case.get("payload")
            if isinstance(p, str) and p and p not in seen:
                seen.add(p)
                payloads.append(p)
    with open(out_path, "w", encoding="utf-8") as out:
        for p in payloads:
            out.write(p + "\n")
    print(f"wrote {len(payloads)} payloads from {len(files)} files -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
