import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { LRUCache } from 'lru-cache';
import pino from 'pino';

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

// ----- Configuration -----
const PORT = process.env.PORT || 8080;
const UPSTREAM_URL = process.env.UPSTREAM_URL || 'https://app.cyberr.ai/backend/api/v1/jobs';
const UPSTREAM_BEARER = process.env.UPSTREAM_BEARER;
if (!UPSTREAM_BEARER) {
  logger.error('Missing UPSTREAM_BEARER env var');
  process.exit(1);
}

const REQUIRE_API_KEY = (process.env.REQUIRE_API_KEY || 'false').toLowerCase() === 'true';
const API_KEY_HEADER = process.env.API_KEY_HEADER || 'x-internal-token';
const API_KEY_VALUE = process.env.MIDDLEWARE_API_KEY || '';
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

// Cache settings
const cacheTTL = Number(process.env.CACHE_TTL_SECONDS || 300);
const cache = new LRUCache({
  max: 500,
  ttl: cacheTTL * 1000
});

// ----- App -----
const app = express();

const TRUST_PROXY = (process.env.TRUST_PROXY || '').toLowerCase();
if (TRUST_PROXY) {
  const parsed = TRUST_PROXY === 'true' ? true : Number.isInteger(Number(TRUST_PROXY)) ? Number(TRUST_PROXY) : TRUST_PROXY;
  app.set('trust proxy', parsed);
}
app.set('etag', false);

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false // keep simple; frontends consuming JSON don't need CSP here
}));
app.use(compression());

// CORS: allow only explicit origins if provided; otherwise disable CORS
if (CORS_ORIGINS.length > 0) {
  app.use(cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, false); // disallow non-browser tools unless same-origin proxy
      if (CORS_ORIGINS.includes(origin)) return callback(null, true);
      return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'HEAD'],
    allowedHeaders: ['Content-Type', API_KEY_HEADER],
    maxAge: 600
  }));
}

// Basic rate limit to prevent abuse
const limiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.RATE_LIMIT_PER_MINUTE || 60),
  standardHeaders: 'draft-8',
  legacyHeaders: false
});
app.use(limiter);

// Health
app.get('/healthz', (req, res) => {
  res.json({ ok: true });
});

// Optional API key middleware for extra protection (server-to-server recommended)
function checkApiKey(req, res, next) {
  if (!REQUIRE_API_KEY) return next();
  const key = req.header(API_KEY_HEADER);
  if (!key || key !== API_KEY_VALUE) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  return next();
}

// Whitelist of allowed query params to forward to upstream
const ALLOWED_PARAMS = new Set(['countries', 'limit', 'offset', 'positions', 'seniority', 'company', 'q']);

// Helper to build upstream URL with filtered query
function buildUpstreamURL(originalQuery) {
  const url = new URL(UPSTREAM_URL);
  // Preserve duplicates for multi-value params like countries
  for (const [k, v] of Object.entries(originalQuery)) {
    if (!ALLOWED_PARAMS.has(k)) continue;
    if (Array.isArray(v)) {
      v.forEach(val => url.searchParams.append(k, String(val)));
    } else {
      url.searchParams.append(k, String(v));
    }
  }
  return url;
}

// GET /jobs -> forwards to upstream with bearer and caches the response
app.get('/jobs', checkApiKey, async (req, res) => {
  try {
    const upstreamURL = buildUpstreamURL(req.query);
    const cacheKey = upstreamURL.toString();

    // Serve from cache if present
    let data = cache.get(cacheKey);
    if (!data) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), Number(process.env.UPSTREAM_TIMEOUT_MS || 8000));

      const resp = await fetch(upstreamURL, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${UPSTREAM_BEARER}`,
          'Accept': 'application/json'
        },
        signal: controller.signal
      }).catch((err) => {
        throw err.name === 'AbortError' ? new Error('Upstream timeout') : err;
      }).finally(() => clearTimeout(timeout));

      if (!resp.ok) {
        const text = await resp.text();
        logger.warn({ status: resp.status, body: text.slice(0, 300) }, 'Upstream non-200');
        return res.status(resp.status).json({ error: 'upstream_error' });
      }

      data = await resp.json();
      cache.set(cacheKey, data);
    }

    // Simple ETag based on string length + first bytes
    const bodyString = JSON.stringify(data);
    const etag = '"' + Buffer.from(bodyString).toString('base64').slice(0, 16) + '"';
    res.set('ETag', etag);
    res.set('Cache-Control', `public, max-age=${Math.max(30, Math.floor(cacheTTL / 2))}`);

    if (req.headers['if-none-match'] === etag) {
      return res.status(304).end();
    }

    return res.json(data);
  } catch (err) {
    logger.error({ err }, 'Middleware error');
    return res.status(502).json({ error: 'bad_gateway' });
  }
});

app.use((err, req, res, next) => {
  logger.warn({ err }, 'Request error');
  const status = (err && (err.status || err.statusCode)) || (/cors/i.test(err?.message || '') ? 403 : undefined);
  res.status(status && Number(status) >= 400 && Number(status) < 600 ? status : 500).json({ error: status === 403 ? 'forbidden' : 'internal_error' });
});

// 404 fallback
app.use((req, res) => res.status(404).json({ error: 'not_found' }));

app.listen(PORT, () => {
  logger.info({ port: PORT, requireApiKey: REQUIRE_API_KEY, corsOrigins: CORS_ORIGINS }, 'Middleware listening');
});