# wafrift-tcpoverlap

Genuine **TCP sequence-overlap** segmentation and **target-based reassembly**
modelling — the Ptacek-Newsham (1998) / Snort `stream5` class of IDS/WAF
evasion, done for real (no fake stub).

When two TCP segments cover the same sequence range with *different* bytes, the
receiver's OS decides which wins — and different stacks decide differently
(`first`/`last`/`bsd`/`linux`/`solaris`). A WAF reassembling one way and the
origin another see **different byte streams** from the same packets: the WAF
sees benign, the origin sees the attack.

- `policy` — the reassembly policies and their precise overlap-resolution rules.
- `reassemble` — simulate reassembly of a segment set under a policy (pure,
  deeply tested against the classic overlap scenarios).
- `plan` — construct overlapping segment sets, and `differential_plan`: emit
  segments that reassemble to *benign* under the WAF's policy and to the *attack*
  under the origin's — self-verified by simulating both before returning.

The planner emits segment descriptors (seq + bytes); a raw-socket transport does
the sending, exactly as the smuggling probes emit wire artifacts.
