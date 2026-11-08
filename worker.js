// Static assets + a same-origin /api/report BFF.
// The control endpoint is a RUNTIME SECRET (env.CONTROL_URL / env.REPORT_TOKEN), set via
// `wrangler secret put CONTROL_URL` — never in this repo or the public page. We forward the
// report to control; control derives ASN/region from the request IP at ingest and DISCARDS the
// IP (SPEC §8.6 + the no-client-IP/destination-logging rule). We log nothing here.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Echo the caller's IP as THIS domain sees it. Used for the silo test: fetch /ip from a
    // tunneled domain (should be the exit) and from a whitelisted/direct domain (should be the
    // real RU IP). We don't log it — it's returned to the caller only.
    if (url.pathname === "/ip") {
      return cors(json({ ip: request.headers.get("cf-connecting-ip"), country: (request.cf && request.cf.country) || null }));
    }
    // Config for the page: the companion (silo-compare) domain comes from env, not the public
    // HTML. `wrangler secret put COMPANION_DOMAIN` on the TUNNELLED probe = the WHITELISTED one.
    if (url.pathname === "/api/config") {
      return cors(json({ companion: env.COMPANION_DOMAIN || null, reporter: !!env.CONTROL_URL }));
    }
    if (url.pathname === "/api/report") {
      if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
      if (request.method !== "POST") return cors(json({ ok: false, error: "POST only" }, 405));
      if (!env.CONTROL_URL) return cors(json({ ok: false, note: "no control configured" }));
      const body = await request.text();
      try {
        const r = await fetch(env.CONTROL_URL, {
          method: "POST",
          headers: { "content-type": "application/json", ...(env.REPORT_TOKEN ? { authorization: `Bearer ${env.REPORT_TOKEN}` } : {}) },
          body,
        });
        return cors(json({ ok: r.ok }));
      } catch {
        return cors(json({ ok: false, error: "forward failed" }, 502));
      }
    }
    return env.ASSETS.fetch(request);
  },
};
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
function cors(resp) {
  resp.headers.set("access-control-allow-origin", "*"); // forward-only; control gates on initData
  resp.headers.set("access-control-allow-methods", "POST, OPTIONS");
  resp.headers.set("access-control-allow-headers", "content-type");
  return resp;
}
