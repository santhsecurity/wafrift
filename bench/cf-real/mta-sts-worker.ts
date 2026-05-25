// mta-sts-worker.ts — minimal Cloudflare Worker that serves the MTA-STS
// policy file at https://mta-sts.santh.dev/.well-known/mta-sts.txt.
//
// Deploy: copy this into its own wrangler project (or add a second
// service to bench/cf-real if you want), set
//   [[routes]]
//   pattern = "mta-sts.santh.dev/.well-known/mta-sts.txt"
//   zone_name = "santh.dev"
// and `npx wrangler deploy`.
//
// Whenever you change the policy, bump the `id` in the _mta-sts TXT
// record so caching senders pick up the new version.

const POLICY = `version: STSv1
mode: enforce
mx: aspmx.l.google.com
mx: alt1.aspmx.l.google.com
mx: alt2.aspmx.l.google.com
mx: alt3.aspmx.l.google.com
mx: alt4.aspmx.l.google.com
max_age: 604800
`;

export default {
    async fetch(req: Request): Promise<Response> {
        const url = new URL(req.url);
        if (url.pathname !== '/.well-known/mta-sts.txt') {
            return new Response('not found', { status: 404 });
        }
        return new Response(POLICY, {
            status: 200,
            headers: {
                'Content-Type': 'text/plain; charset=utf-8',
                'Cache-Control': 'public, max-age=86400',
            },
        });
    },
};
