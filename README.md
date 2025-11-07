# job-middleware

Minimal proxy to fetch jobs from Cyberr API (with upstream Bearer token) and expose a safe, cacheable endpoint for `cybersecurity.lu_v2`.

## Features
- Forwards allowed query params only (`countries`, `limit`, `offset`, etc.)
- Sends upstream **Bearer** from server-side env (never exposed to the browser)
- In-memory cache (LRU) with TTL
- Optional API key gate for server-to-server usage
- Strict CORS allow-list (optional)
- Rate limiting and sensible timeouts
- ETag + Cache-Control for client-side caching
- Dockerized

## Run locally
```bash
cp .env.example .env   # fill UPSTREAM_BEARER
docker compose up --build
# -> http://localhost:8002/jobs?countries=LU&countries=FR&limit=100&offset=0
```

## Env vars
See `.env.example` for all options.

## Integration (frontend)
Deploy the middleware on a dedicated domain (e.g. `https://cyberr-proxy.cybersecurity.lu`). React app can call:

```js
const url = 'https://cyberr-proxy.cybersecurity.lu/jobs?countries=LU&countries=FR&limit=100&offset=0';
const res = await fetch(url, { method: 'GET' });
const data = await res.json();
```

If you enable `REQUIRE_API_KEY=true` (server-to-server), add the header from your backend only:

```bash
curl -H "x-internal-token: $MIDDLEWARE_API_KEY" https://cyberr-proxy.cybersecurity.lu/jobs
```

## Security notes
- Never ship the upstream Bearer to the browser. Keep it server-side.
- Prefer a dedicated domain or subdomain and restrict CORS allow-list accordingly to avoid exposing extra surface.
- API keys in client-side JS are **not secrets**; use `REQUIRE_API_KEY=true` only for backends.
```