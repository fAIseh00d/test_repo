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
    // Config for the page: the companion (silo-compare) domain and this domain's EXPECTED route
    // come from env, not the public HTML. Per deployment:
    //   `wrangler secret put EXPECTED_ROUTE`  -> "tunnel" (egress SHOULD be the VPN exit) on the
    //                                            tunnelled probe, or "direct" (egress SHOULD be the
    //                                            real RU IP) on the whitelisted/direct probe.
    //   `wrangler secret put COMPANION_DOMAIN` -> the OTHER probe (opposite role) for the cross-check.
    // expected defaults to null (role not configured -> informational verdict only).
    if (url.pathname === "/api/config") {
      const expected = env.EXPECTED_ROUTE === "tunnel" || env.EXPECTED_ROUTE === "direct" ? env.EXPECTED_ROUTE : null;
      // directDomain/proxiedDomain feed the connectivity Mini App's two reachability checks.
      // They are env secrets (per deployment), never baked into the public page.
      return cors(json({
        companion: env.COMPANION_DOMAIN || null,
        reporter: !!env.CONTROL_URL,
        expected,
        directDomain: env.DIRECT_PROBE_DOMAIN || null,
        proxiedDomain: env.PROXIED_PROBE_DOMAIN || null,
      }));
    }
    // Connectivity Mini App BFF: validate Telegram initData here (the bot token never reaches the
    // browser), then post one connectivity signal to control keyed to the user's tg_id. On invalid
    // initData we 401 and never touch control. No IP / domain / URL is logged.
    if (url.pathname === "/api/connectivity") {
      if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
      if (request.method !== "POST") return cors(json({ ok: false, error: "POST only" }, 405));
      let body;
      try { body = await request.json(); } catch { return cors(json({ ok: false, error: "bad json" }, 400)); }
      if (!body || typeof body.initData !== "string" || !body.initData) {
        return cors(json({ ok: false, error: "initData required" }, 400));
      }
      if (!env.BOT_TOKEN) return cors(json({ ok: false, error: "not configured" }, 500));
      const maxAge = Number(env.INITDATA_MAX_AGE_SECS) > 0 ? Number(env.INITDATA_MAX_AGE_SECS) : 3600;
      const v = await verifyInitData(body.initData, env.BOT_TOKEN, maxAge);
      if (!v.ok) return cors(json({ ok: false, error: "unauthorized" }, 401));
      if (!env.CONTROL_URL || !env.SERVICE_TOKEN) return cors(json({ ok: false, note: "no control configured" }));
      const payload = { direct_ok: !!body.direct_ok, proxied_ok: !!body.proxied_ok };
      if (Number.isFinite(body.asn)) payload.asn = body.asn >>> 0; // u32
      const base = String(env.CONTROL_URL).replace(/\/+$/, "");
      try {
        const r = await fetch(`${base}/v1/int/user/${v.tgId}/connectivity`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${env.SERVICE_TOKEN}` },
          body: JSON.stringify(payload),
        });
        return cors(json({ ok: r.ok }));
      } catch {
        return cors(json({ ok: false, error: "forward failed" }, 502));
      }
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
// ── Telegram WebApp initData validation (per Telegram's Mini App spec) ────────────
// data_check_string = every "key=value" except `hash`, sorted by key, joined with "\n".
// secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token).
// valid when hex(HMAC_SHA256(key=secret_key, msg=data_check_string)) === hash.
// Then require a fresh auth_date (within maxAgeSecs) and extract user.id.
async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
// Constant-time compare of two equal-length hex strings (length mismatch -> not equal).
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function verifyInitData(initData, botToken, maxAgeSecs) {
  let params;
  try { params = new URLSearchParams(initData); } catch { return { ok: false }; }
  const hash = params.get("hash");
  if (!hash) return { ok: false };
  params.delete("hash"); // only `hash` is removed; `signature`, if present, stays in the string
  const pairs = [];
  for (const [k, val] of params) pairs.push(`${k}=${val}`);
  pairs.sort();
  const dataCheckString = pairs.join("\n");
  const enc = new TextEncoder();
  const secretKey = await hmacSha256(enc.encode("WebAppData"), enc.encode(botToken));
  const computed = toHex(await hmacSha256(secretKey, enc.encode(dataCheckString)));
  if (!timingSafeEqual(computed, String(hash).toLowerCase())) return { ok: false };
  const authDate = Number(params.get("auth_date"));
  if (!Number.isFinite(authDate) || authDate <= 0) return { ok: false };
  const age = Math.floor(Date.now() / 1000) - authDate;
  if (age < -60 || age > maxAgeSecs) return { ok: false }; // stale (small negative clock skew allowed)
  let tgId = null;
  try { tgId = JSON.parse(params.get("user") || "null")?.id; } catch { /* no user */ }
  if (!Number.isFinite(tgId)) return { ok: false };
  return { ok: true, tgId };
}
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
function cors(resp) {
  resp.headers.set("access-control-allow-origin", "*"); // forward-only; control gates on initData
  resp.headers.set("access-control-allow-methods", "POST, OPTIONS");
  resp.headers.set("access-control-allow-headers", "content-type");
  return resp;
}
