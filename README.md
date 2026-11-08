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
