// server.js
const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { URL } = require('url');

const app = express();

// Config
const RATE_WINDOW_MS = parseInt(process.env.RATE_WINDOW_MS || '60000', 10); // 60s
const RATE_MAX = parseInt(process.env.RATE_MAX || '60', 10); // requests per window
const API_KEY = process.env.API_KEY || ''; // optional: set to require X-API-Key header

// Middleware
app.use(helmet());
app.use(express.urlencoded({ extended: true })); // for form POSTs from homepage
app.use(express.json({ limit: '5mb' }));

const limiter = rateLimit({
  windowMs: RATE_WINDOW_MS,
  max: RATE_MAX,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for'] || 'unknown',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Helpers
function requireApiKey(req, res) {
  if (!API_KEY) return true;
  const key = req.get('X-API-Key') || req.query.api_key;
  if (!key || key !== API_KEY) {
    res.status(401).send('Missing or invalid API key');
    return false;
  }
  return true;
}

function sanitizeForwardHeaders(origHeaders) {
  const out = {};
  for (const [k, v] of Object.entries(origHeaders || {})) {
    const lk = k.toLowerCase();
    if (['host', 'connection', 'content-length', 'upgrade', 'expect'].includes(lk)) continue;
    out[k] = v;
  }
  return out;
}

function proxyUrlFor(target) {
  return '/proxy?url=' + encodeURIComponent(target);
}

function absoluteUrl(base, relative) {
  try {
    return new URL(relative, base).toString();
  } catch {
    return relative;
  }
}

// Homepage with URL bar
app.get('/', (req, res) => {
  res.send(`<!doctype html>
  <html>
  <head>
    <meta charset="utf-8">
    <title>Node Web Proxy</title>
    <style>
      body{font-family:Arial,Helvetica,sans-serif;background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
      .card{background:rgba(255,255,255,0.06);padding:22px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,0.4)}
      input[type=text]{padding:10px;border-radius:8px;border:none;width:420px}
      button{padding:10px 14px;border-radius:8px;border:none;margin-left:8px;background:#10b981;color:#fff;cursor:pointer}
      .small{font-size:13px;color:#cbd5e1;margin-top:8px}
    </style>
  </head>
  <body>
    <div class="card">
      <h2>🌐 Web Proxy</h2>
      <form method="GET" action="/proxy">
        <input type="text" name="url" placeholder="https://example.com" required />
        <button type="submit">Go</button>
      </form>
      <div class="small">Tip: paste a full URL including http(s)://</div>
    </div>
  </body>
  </html>`);
});

// Health
app.get('/_health', (req, res) => res.send('OK'));

// GET proxy
app.get('/proxy', async (req, res) => {
  if (!requireApiKey(req, res)) return;
  const raw = req.query.url;
  if (!raw) return res.status(400).send('missing url parameter');

  let target;
  try {
    target = decodeURIComponent(raw);
  } catch {
    target = raw;
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch (err) {
    return res.status(400).send('invalid url');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).send('unsupported scheme');

  // Forward headers (filtered)
  const forwardHeaders = sanitizeForwardHeaders(req.headers);

  try {
    // Use axios to fetch; allow redirects
    const upstream = await axios({
      method: 'get',
      url: target,
      headers: forwardHeaders,
      responseType: 'arraybuffer',
      validateStatus: () => true,
      timeout: 20000,
      maxRedirects: 5,
    });

    const contentType = upstream.headers['content-type'] || '';

    // If HTML, rewrite links
    if (contentType.toLowerCase().includes('text/html')) {
      try {
        const html = upstream.data.toString('utf8');
        const $ = cheerio.load(html, { decodeEntities: false });

        const base = upstream.request?.res?.responseUrl || target;

        // rewrite attributes
        const mapping = [
          ['a', 'href'],
          ['link', 'href'],
          ['script', 'src'],
          ['img', 'src'],
          ['iframe', 'src'],
          ['source', 'src'],
        ];

        mapping.forEach(([tag, attr]) => {
          $(tag).each((i, el) => {
            const $el = $(el);
            const val = $el.attr(attr);
            if (!val) return;
            const abs = absoluteUrl(base, val);
            $el.attr(attr, proxyUrlFor(abs));
          });
        });

        // forms: set action to proxied endpoint
        $('form').each((i, el) => {
          const $el = $(el);
          const action = $el.attr('action') || base;
          const abs = absoluteUrl(base, action);
          $el.attr('action', proxyUrlFor(abs));
          // ensure method attribute exists
          if (!$el.attr('method')) $el.attr('method', 'post');
        });

        // send rewritten HTML
        res.set('Content-Type', 'text/html; charset=utf-8');
        return res.status(upstream.status).send($.html());
      } catch (e) {
        return res.status(500).send('html rewrite error: ' + String(e));
      }
    }

    // Non-HTML: stream raw bytes
    res.status(upstream.status);
    if (upstream.headers['content-type']) res.set('Content-Type', upstream.headers['content-type']);
    if (upstream.headers['content-length']) res.set('Content-Length', upstream.headers['content-length']);
    if (upstream.headers['content-disposition']) res.set('Content-Disposition', upstream.headers['content-disposition']);

    return res.send(Buffer.from(upstream.data));
  } catch (err) {
    console.error('upstream error', err && err.toString());
    return res.status(502).send('upstream fetch error');
  }
});

// POST proxy (forms)
app.post('/proxy', express.raw({ type: '*/*', limit: '10mb' }), async (req, res) => {
  if (!requireApiKey(req, res)) return;
  const raw = req.query.url;
  if (!raw) return res.status(400).send('missing url parameter');

  let target;
  try {
    target = decodeURIComponent(raw);
  } catch {
    target = raw;
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return res.status(400).send('invalid url');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).send('unsupported scheme');

  const forwardHeaders = sanitizeForwardHeaders(req.headers);

  try {
    const upstream = await axios({
      method: 'post',
      url: target,
      headers: forwardHeaders,
      data: req.body,
      responseType: 'arraybuffer',
      validateStatus: () => true,
      timeout: 20000,
      maxRedirects: 5,
    });

    const contentType = upstream.headers['content-type'] || '';
    if (contentType.toLowerCase().includes('text/html')) {
      try {
        const html = upstream.data.toString('utf8');
        const $ = cheerio.load(html, { decodeEntities: false });
        const base = upstream.request?.res?.responseUrl || target;

        const mapping = [
          ['a', 'href'],
          ['link', 'href'],
          ['script', 'src'],
          ['img', 'src'],
          ['iframe', 'src'],
          ['source', 'src'],
        ];
        mapping.forEach(([tag, attr]) => {
          $(tag).each((i, el) => {
            const $el = $(el);
            const val = $el.attr(attr);
            if (!val) return;
            const abs = absoluteUrl(base, val);
            $el.attr(attr, proxyUrlFor(abs));
          });
        });
        $('form').each((i, el) => {
          const $el = $(el);
          const action = $el.attr('action') || base;
          const abs = absoluteUrl(base, action);
          $el.attr('action', proxyUrlFor(abs));
          if (!$el.attr('method')) $el.attr('method', 'post');
        });

        res.set('Content-Type', 'text/html; charset=utf-8');
        return res.status(upstream.status).send($.html());
      } catch (e) {
        return res.status(500).send('html rewrite error: ' + String(e));
      }
    }

    res.status(upstream.status);
    if (upstream.headers['content-type']) res.set('Content-Type', upstream.headers['content-type']);
    if (upstream.headers['content-length']) res.set('Content-Length', upstream.headers['content-length']);
    if (upstream.headers['content-disposition']) res.set('Content-Disposition', upstream.headers['content-disposition']);
    return res.send(Buffer.from(upstream.data));
  } catch (err) {
    console.error('upstream error', err && err.toString());
    return res.status(502).send('upstream fetch error');
  }
});

// Start
const port = parseInt(process.env.PORT || '3000', 10);
app.listen(port, () => {
  console.log(`Proxy listening on port ${port}`);
});
