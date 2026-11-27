# Deploying `vectoll.org` and `vectoll.com`

Both flagship Vectoll web applications are self-contained, zero-dependency static bundles (HTML + CSS + ES2022 WebCrypto JS + embedded `/brand/*` SVGs + `/.well-known/vectoll.json`).

## Local Preview
```bash
pnpm run web
# vectoll.org -> http://127.0.0.1:4030
# vectoll.com -> http://127.0.0.1:4031
```

## Deploy to Cloudflare Pages / Vercel / Netlify
Create two projects pointing to this repository:

| Domain | Root / Publish Directory | Build Command |
| :--- | :--- | :--- |
| **`vectoll.org`** | `apps/web/org` | `node apps/web/sync-static.mjs` (or none — pre-built in repo) |
| **`vectoll.com`** | `apps/web/com` | `node apps/web/sync-static.mjs` (or none — pre-built in repo) |

## Deploy on a VPS (Nginx / Caddy)
With Caddy (`Caddyfile` — automatic HTTPS certificates):
```caddyfile
vectoll.org, www.vectoll.org {
    root * /var/www/vectoll/apps/web/org
    encode zstd gzip
    file_server
}

vectoll.com, www.vectoll.com {
    root * /var/www/vectoll/apps/web/com
    encode zstd gzip
    file_server
}
```
