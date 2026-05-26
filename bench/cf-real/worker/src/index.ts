// wafrift bench/cf-real Worker — INTENTIONALLY VULNERABLE.
//
// Purpose: serve a small surface the operator can fire wafrift
// payloads at THROUGH a real Cloudflare WAF (the zone's Custom
// Rules + Managed Rules). The Worker itself does NOT execute the
// payload — every endpoint is an echo / harmless concat so a
// "successful bypass" means "the WAF didn't block" and the
// Worker's response can confirm the payload reached origin
// verbatim.
//
// Isolation invariants (per the operator's design ask):
//   - No database, no filesystem, no external HTTP fetch.
//   - No KV / R2 / D1 writes from request handlers (the Worker
//     is stateless across requests).
//   - No environment secrets read from request handlers
//     (preview tokens / keys live only in wrangler.toml secrets
//     and are not echoed even on /env).
//   - Every response is bounded at 8 KiB so an attacker can't
//     pivot to amplification.
//   - The CORS policy allows only the wafrift bench origin.
//
// What lives where:
//   - GET   /            — index + endpoint catalog
//   - GET   /echo?q=…     — echoes q back (URL-query attack surface)
//   - GET   /headers      — JSON of the request headers (header attack surface)
//   - POST  /form         — echoes form fields (form attack surface)
//   - POST  /json         — echoes JSON body fields (JSON attack surface)
//   - GET   /redirect?to= — 302s to the URL (open redirect — only for
//                            wafrift's redirect-handling tests, NOT
//                            an SSRF — `to` is bounded to https://*
//                            on the same zone)
//   - GET   /sql?id=…     — concats id into a STRING (no actual SQL),
//                            for "did the WAF strip the payload" tests
//   - GET   /reflect-cookie?name=…  — Set-Cookie with the supplied name
//                                      (Set-Cookie injection surface)
//   - GET   /reflect-status?code=N  — returns the requested status
//                                      (CL/TE smuggling probes)
//
// Hand-off: deploy with `wrangler deploy`, then point wafrift at
// the resulting URL via `cargo run --bin wafrift -- bench-waf
// --target https://wafrift-bench.<account>.workers.dev`.

const MAX_BYTES = 8192;

function clamp(s: string): string {
    if (s.length > MAX_BYTES) return s.slice(0, MAX_BYTES) + '\n[... truncated]';
    return s;
}

function json(body: unknown, status = 200): Response {
    return new Response(clamp(JSON.stringify(body)), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
        },
    });
}

export default {
    async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url);
        const path = url.pathname;

        if (path === '/' || path === '/index') {
            return json({
                name: 'wafrift bench/cf-real',
                doc: 'see bench/cf-real/README.md',
                endpoints: [
                    'GET  /echo?q=…',
                    'GET  /headers',
                    'POST /form (Content-Type: application/x-www-form-urlencoded)',
                    'POST /json (Content-Type: application/json)',
                    'GET  /redirect?to=…',
                    'GET  /sql?id=…',
                    'GET  /reflect-cookie?name=…',
                    'GET  /reflect-status?code=N',
                ],
            });
        }

        if (path === '/echo' || path === '/get') {
            // `/get?q=…` is the canonical query-carrier the
            // wafrift-bench corpus targets — every `*.toml` case
            // with `delivery = "query"` lands here. Aliasing it to
            // /echo lets the unmodified bench-waf binary point at
            // this worker without any per-target adapter, which is
            // what the CF Pro live-bench needs to mean anything.
            const q = url.searchParams.get('q') ?? '';
            // Reflect every query parameter so the bench's
            // multi-param probes also see their inputs round-tripped
            // — needed for the Tsai-class param-pollution variants.
            const args: Record<string, string> = {};
            for (const [k, v] of url.searchParams.entries()) {
                args[k] = clamp(v);
            }
            return json({ q: clamp(q), args });
        }

        if (path === '/headers') {
            const hdrs: Record<string, string> = {};
            for (const [k, v] of req.headers.entries()) {
                // Skip CF-internal headers — we don't want the
                // bench leaking trust info that helps an attacker
                // distinguish CF's behaviour.
                if (k.toLowerCase().startsWith('cf-')) continue;
                hdrs[k] = clamp(v);
            }
            return json({ headers: hdrs });
        }

        // `/form` AND `/post` both accept form-encoded body.
        // `/post` is the default endpoint wafrift's bench-waf
        // fires against — alias both so existing payload
        // corpora work without renaming.
        if ((path === '/form' || path === '/post') && req.method === 'POST') {
            const form = await req.formData().catch(() => null);
            if (!form) return json({ error: 'bad form' }, 400);
            const out: Record<string, string> = {};
            for (const [k, v] of form.entries()) {
                if (typeof v === 'string') out[k] = clamp(v);
            }
            return json({ form: out });
        }

        if (path === '/json' && req.method === 'POST') {
            // F88: cap the input by raw text first. `json({...})`
            // calls `clamp(JSON.stringify(...))`, which truncates the
            // SERIALIZED form mid-token if `body` is a large nested
            // object — leaving the response as invalid JSON (e.g.
            // `{"received":{"a":"AAAA...`). Bound at the text level
            // before parse so the truncation contract holds.
            const raw = await req.text();
            if (raw.length > MAX_BYTES) {
                return json({ error: 'body too large' }, 413);
            }
            let body: unknown;
            try {
                body = JSON.parse(raw);
            } catch {
                return json({ error: 'bad json' }, 400);
            }
            return json({ received: body });
        }

        if (path === '/redirect') {
            const to = url.searchParams.get('to') ?? '';
            // Only allow same-zone https targets so this Worker
            // can't be turned into a generic open redirect.
            // F133: pre-fix used `dest.hostname.endsWith(url.hostname)`
            // which is a string-suffix check — `attackerexample.com`
            // ends with `example.com`, `evil-wafrift-bench.acct.
            // workers.dev` ends with `wafrift-bench.acct.workers.dev`.
            // The "same-zone" guard accepted foreign hosts as long as
            // their name string ended with the Worker's hostname,
            // breaking the bench's isolation invariant. Allow only
            // the exact host OR a true subdomain (boundary at `.`).
            try {
                const dest = new URL(to);
                const sameHost = dest.hostname === url.hostname;
                const trueSubdomain =
                    dest.hostname.endsWith('.' + url.hostname) &&
                    dest.hostname.length > url.hostname.length + 1;
                if (
                    dest.protocol !== 'https:' ||
                    !(sameHost || trueSubdomain)
                ) {
                    return json({ error: 'cross-origin redirect refused' }, 400);
                }
                return Response.redirect(dest.toString(), 302);
            } catch {
                return json({ error: 'malformed url' }, 400);
            }
        }

        if (path === '/sql') {
            const id = url.searchParams.get('id') ?? '';
            // NOT a real query — string-concat into a fake SELECT
            // for the operator to confirm the payload bytes
            // reached origin verbatim.
            const faked = `SELECT * FROM users WHERE id = '${id}'`;
            return json({ would_have_run: clamp(faked) });
        }

        if (path === '/reflect-cookie') {
            const name = url.searchParams.get('name') ?? '';
            // Bounded set-cookie reflect — the WAF may block
            // payloads that try to smuggle a Set-Cookie header.
            const headers = new Headers({ 'Content-Type': 'application/json' });
            // RFC 6265 disallows several chars in cookie names;
            // we let the WAF and the CF edge enforce that.
            headers.append('Set-Cookie', `${clamp(name)}=ok; Path=/; HttpOnly`);
            return new Response(JSON.stringify({ ok: true }), { headers });
        }

        if (path === '/reflect-status') {
            const code = parseInt(url.searchParams.get('code') ?? '200', 10);
            const clamped = code >= 100 && code < 600 ? code : 200;
            return json({ requested_status: clamped }, clamped);
        }

        return json({ error: 'not found' }, 404);
    },
};
