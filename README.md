# leak-probe

Connection check (what a hostile RU site / Telegram Mini App learns): auto-runs on load, shows a
verdict, raw results under **Advanced**. Egress IP + country, WebRTC (STUN srflx = exit IP),
blocked-domain reachability, timezone mismatch.

## Architecture (no control domain in public)
- Static page served by a Cloudflare **Worker** (`worker.js`) from `public/`.
- The page POSTs results to its **own origin** `/api/report`. The Worker forwards to control using
  **runtime secrets** — the control endpoint is never in this repo or the page:
  ```
  npx wrangler secret put CONTROL_URL     # e.g. the miniapp BFF / control app port
  npx wrangler secret put REPORT_TOKEN    # scoped bearer
  ```
- GitHub Pages (static, no Worker) is a **report-less fallback**: the probe runs, `/api/report`
  404s, reporting skips silently.

Deploy: `npx wrangler deploy`. Hosts: probe-00 (Cloudflare Worker, reports), probe-01 (GitHub Pages, fallback).

## Connectivity check (`connectivity.html`)

A second page for in-Telegram use: it runs a baseline-internet reachability check and a
through-the-tunnel reachability check, derives `direct_ok` / `proxied_ok`, and POSTs one signal
to its **own origin** `/api/connectivity`. The Worker validates Telegram `initData` server-side
(HMAC-SHA256 per the Mini App spec: `secret = HMAC_SHA256(key="WebAppData", msg=bot_token)`, then
`hash == HMAC_SHA256(key=secret, msg=data_check_string)`, plus a freshness window on `auth_date`),
extracts the user id, and forwards `{direct_ok, proxied_ok, asn?}` to the control endpoint with a
scoped service token. Invalid `initData` is rejected `401` and control is never contacted. The bot
token never reaches the browser.

Secrets (all via `wrangler secret put`, never committed):
```
npx wrangler secret put BOT_TOKEN              # Telegram bot token — validates initData (stays server-side)
npx wrangler secret put SERVICE_TOKEN          # scoped bearer for the control endpoint
npx wrangler secret put CONTROL_URL            # control BASE origin; the route POSTs {CONTROL_URL}/v1/int/user/{id}/connectivity
npx wrangler secret put DIRECT_PROBE_DOMAIN    # (optional) a plainly-reachable domain -> baseline internet up
npx wrangler secret put PROXIED_PROBE_DOMAIN   # (optional) a domain that answers only through the tunnel
npx wrangler secret put INITDATA_MAX_AGE_SECS  # (optional) auth_date freshness window; default 3600
```
Note: for the leak-probe `/api/report` route, `CONTROL_URL` is the full report URL; for the
connectivity route it is the control base origin (the path is appended). Deploy them as separate
Workers, or point `CONTROL_URL` at a base that serves both.
