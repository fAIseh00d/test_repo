# reachability probe

A tiny public API used to check which network path a request took. No pages, no secrets,
no configuration, nothing stored or logged.

| Path | Answer |
|---|---|
| `GET /ip` | `{"ip", "country", "asn", "org"}`: the address (and its network) this hostname saw the request come from |
| `GET /ping` | `204` (the static-hosting copy answers `200 ok`) |

The same repository deploys two ways:
- **Cloudflare Workers** (`worker.js` + `public/`): `/ip` and `/ping`. Deploy with `npx wrangler deploy`,
  or connect the repo in the Cloudflare dashboard.
- **GitHub Pages** (`public/` only, `.github/workflows/pages.yml`): static, so only `/ping`.

`robots.txt` disallows everything, and the Worker sends `X-Robots-Tag: noindex`.
