// Reachability probe: a tiny public API, no pages, no secrets, no configuration.
//
//   GET /ip    -> {"ip": "<address this hostname saw>", "country": "<2-letter>"}
//   GET /ping  -> 204
//
// The same code runs on several hostnames; the caller compares what each one saw (for example
// one hostname reached through a tunnel and one reached directly). Nothing is stored or logged:
// the address is returned to the caller and forgotten.
// Static files in public/ (robots.txt, ping) are shared with the static-hosting copy of this repo,
// which can only answer /ping.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return headers(new Response(null, { status: 204 }));
    if (request.method !== "GET" && request.method !== "HEAD") {
      return headers(new Response(null, { status: 405 }));
    }
    if (url.pathname === "/ip") {
      const body = JSON.stringify({
        ip: request.headers.get("cf-connecting-ip"),
        country: (request.cf && request.cf.country) || null,
      });
      return headers(new Response(body, { headers: { "content-type": "application/json" } }));
    }
    if (url.pathname === "/ping") return headers(new Response(null, { status: 204 }));
    if (url.pathname === "/robots.txt") return headers(await env.ASSETS.fetch(request));
    return headers(new Response("Not found", { status: 404 }));
  },
};

function headers(resp) {
  const r = new Response(resp.body, resp);
  r.headers.set("access-control-allow-origin", "*");
  r.headers.set("access-control-allow-methods", "GET, OPTIONS");
  r.headers.set("cache-control", "no-store");
  r.headers.set("x-robots-tag", "noindex, nofollow");
  r.headers.set("x-content-type-options", "nosniff");
  return r;
}
