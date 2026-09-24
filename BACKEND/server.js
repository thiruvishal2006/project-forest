const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const crypto = require('node:crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit').rateLimit;
const db = require('./db');
const { analyzeDevice, calculateForSavedDevice, decodeAnalysis } = require('./risk-engine');
const { normalizeUsbId } = require('./usb-intelligence');

function envInteger(name, fallback, min, max) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer.`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} is outside its allowed range.`);
  return value;
}

const port = envInteger('PORT', 5000, 1, 65535);
const host = process.env.HOST || '0.0.0.0';
const proxyHops = envInteger('TRUST_PROXY', 0, 0, 10);
const requestLimit = envInteger('MAX_REQUEST_SIZE_BYTES', 32768, 1024, 1048576);
const apiWindowMs = envInteger('API_RATE_LIMIT_WINDOW_MS', 60000, 1000, 3600000);
const apiLimit = envInteger('API_RATE_LIMIT_MAX', 120, 1, 10000);
const analysisLimit = envInteger('ANALYSIS_RATE_LIMIT_MAX', 30, 1, 10000);
const isProduction = process.env.NODE_ENV === 'production';
if (process.env.REANALYZE_TOKEN && (process.env.REANALYZE_TOKEN.length < 32 || /replace|example|changeme/i.test(process.env.REANALYZE_TOKEN))) {
  throw new Error('REANALYZE_TOKEN must be a unique secret of at least 32 characters.');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', proxyHops);
app.use(helmet({
  hsts: false,
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], baseUri: ["'self'"], connectSrc: ["'self'"],
    fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
    formAction: ["'self'"], frameAncestors: ["'none'"], imgSrc: ["'self'", 'data:'],
    objectSrc: ["'none'"], scriptSrc: ["'self'"], styleSrc: ["'self'", 'https://fonts.googleapis.com'],
    ...(isProduction ? { upgradeInsecureRequests: [] } : {})
  } },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (isProduction && req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  if (req.originalUrl.length > 4096) return fail(res, 414, 'Request URL is too long.');
  next();
});

function fail(res, status, message) {
  return res.status(status).json({ success: false, message });
}

function createRateLimiter(limit, scope, windowMs = apiWindowMs) {
  return rateLimit({
    windowMs, limit, standardHeaders: 'draft-8', legacyHeaders: false,
    handler: (_req, res) => {
      console.warn(JSON.stringify({ event: 'rate_limit.exceeded', scope }));
      fail(res, 429, 'Too many requests. Try again later.');
    }
  });
}
const apiRateLimiter = createRateLimiter(apiLimit, 'api');
const analysisRateLimiter = createRateLimiter(analysisLimit, 'analysis');
app.use('/api', apiRateLimiter);
app.use(express.json({ limit: requestLimit, strict: true }));

function normalizeDevice(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'A JSON object is required.';
  const { deviceName, vendorId, productId } = body;
  if (typeof deviceName !== 'string' || !deviceName.trim()) return 'Device name is required.';
  if (typeof vendorId !== 'string' || !vendorId.trim()) return 'Vendor ID is required.';
  if (typeof productId !== 'string' || !productId.trim()) return 'Product ID is required.';
  if (body.serial !== undefined && typeof body.serial !== 'string') return 'Serial number must be text.';
  if (body.deviceClass !== undefined && !['unknown', 'hid', 'mass_storage', 'composite', 'other'].includes(body.deviceClass)) {
    return 'Device class must be unknown, hid, mass_storage, composite, or other.';
  }
  const name = deviceName.trim();
  const serial = (body.serial || '').trim();
  if (name.length > 120 || vendorId.trim().length > 32 || productId.trim().length > 32 || serial.length > 128) {
    return 'One or more fields exceed the maximum length.';
  }
  const normalizedVendorId = normalizeUsbId(vendorId);
  const normalizedProductId = normalizeUsbId(productId);
  if (!normalizedVendorId) return 'Vendor ID must be a 16-bit hexadecimal ID, such as 0781 or 0x0781.';
  if (!normalizedProductId) return 'Product ID must be a 16-bit hexadecimal ID, such as 5567 or 0x5567.';
  return { deviceName: name, vendorId: normalizedVendorId, productId: normalizedProductId, serial, deviceClass: body.deviceClass || 'unknown' };
}

function serializeDevice(row) {
  const { factors: _storedFactors, serial, ...device } = row;
  const analysis = decodeAnalysis(row);
  return { ...device, serialPresent: Boolean(serial), ...analysis, risk_factors: analysis.riskFactors };
}

function sendError(error, _req, res, _next) {
  if (res.headersSent) return;
  if (error instanceof SyntaxError && 'body' in error) return fail(res, 400, 'Invalid JSON body.');
  if (error?.type === 'entity.too.large') return fail(res, 413, 'Request body is too large.');
  if (error?.type === 'encoding.unsupported' || error?.type === 'charset.unsupported') return fail(res, 415, 'Unsupported request encoding.');
  console.error(JSON.stringify({ event: 'request.error', message: String(error?.message || 'unknown error').slice(0, 160) }));
  return fail(res, 500, 'Internal server error.');
}

function parseDeviceId(raw) {
  if (!/^[1-9]\d{0,14}$/.test(raw)) return null;
  const id = Number(raw);
  return Number.isSafeInteger(id) ? id : null;
}

function bearerMatches(req, expected) {
  const match = /^Bearer ([\x21-\x7e]{16,512})$/.exec(req.get('authorization') || '');
  if (!match || !expected) return false;
  const provided = Buffer.from(match[1]);
  const secret = Buffer.from(expected);
  return provided.length === secret.length && crypto.timingSafeEqual(provided, secret);
}

app.get(['/health', '/api/health'], (_req, res) => res.json({ success: true, data: { status: 'ok' } }));

app.post('/api/analyze', analysisRateLimiter, (req, res, next) => {
  const fields = normalizeDevice(req.body);
  if (typeof fields === 'string') return fail(res, 400, fields);
  try {
    const analysis = analyzeDevice(fields);
    const scannedAt = new Date().toISOString();
    const saved = db.insertDevice.run({
      ...fields,
      serial: fields.serial ? 'provided' : '',
      riskScore: analysis.riskScore,
      verdict: analysis.verdict,
      factors: JSON.stringify(analysis),
      scannedAt
    });
    const result = serializeDevice({ id: Number(saved.lastInsertRowid), ...fields, serial: fields.serial ? 'provided' : '', ...analysis, factors: JSON.stringify(analysis), scannedAt });
    console.info(JSON.stringify({ event: 'usb.analysis.completed', vid: fields.vendorId, pid: fields.productId, riskScore: analysis.riskScore, verdict: analysis.verdict, factorCodes: analysis.riskFactors.map((factor) => factor.code) }));
    res.status(201).json({ success: true, data: result });
  } catch (error) { next(error); }
});

app.get('/api/devices', (req, res, next) => {
  const keys = Object.keys(req.query);
  if (keys.some((key) => !['page', 'limit'].includes(key))) return fail(res, 400, 'Only page and limit query parameters are supported.');
  const integerParam = (key, fallback, max) => {
    const raw = req.query[key];
    if (raw === undefined) return fallback;
    if (typeof raw !== 'string' || !/^\d{1,8}$/.test(raw)) return null;
    const value = Number(raw);
    return value >= 1 && value <= max ? value : null;
  };
  const page = integerParam('page', 1, 1000000);
  const limit = integerParam('limit', 50, 100);
  if (page === null || limit === null) return fail(res, 400, 'Page must be 1–1000000 and limit must be 1–100.');
  try {
    res.set({ 'X-Page': String(page), 'X-Page-Size': String(limit) });
    res.json({ success: true, data: db.listDevices(limit, (page - 1) * limit).map(serializeDevice) });
  } catch (error) { next(error); }
});

app.get('/api/reports/:id', (req, res, next) => {
  const id = parseDeviceId(req.params.id);
  if (!id) return fail(res, 400, 'Report ID must be a positive integer.');
  try {
    const report = db.getDevice(id);
    if (!report) return fail(res, 404, 'Device report not found.');
    res.json({ success: true, data: serializeDevice(report) });
  } catch (error) { next(error); }
});

app.post('/api/devices/:id/reanalyze', analysisRateLimiter, (req, res, next) => {
  const expected = process.env.REANALYZE_TOKEN;
  if (!expected) return fail(res, 404, 'API route not found.');
  if (!bearerMatches(req, expected)) return fail(res, 401, 'Administrator authorization required.');
  const id = parseDeviceId(req.params.id);
  if (!id) return fail(res, 400, 'Device ID must be a positive integer.');
  try {
    const saved = db.getDevice(id);
    if (!saved) return fail(res, 404, 'Device not found.');
    const analysis = calculateForSavedDevice(saved);
    db.updateDeviceAnalysis.run({ id, vendorId: analysis.device.vid, productId: analysis.device.pid, riskScore: analysis.riskScore, verdict: analysis.verdict, factors: JSON.stringify(analysis) });
    const refreshed = db.getDevice(id);
    console.info(JSON.stringify({ event: 'usb.analysis.reanalyzed', id, vid: analysis.device.vid, pid: analysis.device.pid, riskScore: analysis.riskScore, factorCodes: analysis.riskFactors.map((factor) => factor.code) }));
    res.json({ success: true, data: serializeDevice(refreshed) });
  } catch (error) { next(error); }
});

app.use('/api', (req, res) => {
  if (req.path === '/analyze' || req.path === '/devices' || /^\/devices\/[^/]+\/reanalyze$/.test(req.path) || /^\/reports\/[^/]+$/.test(req.path)) {
    res.setHeader('Allow', 'GET, POST');
    return fail(res, 405, 'Method not allowed.');
  }
  return fail(res, 404, 'API route not found.');
});
app.use((_req, res) => res.status(404).type('text/plain').send('Not found.'));
app.use(sendError);

if (require.main === module) app.listen(port, host, () => console.log(`USB analyzer listening on http://${host}:${port}`));
module.exports = { app, normalizeDevice, createRateLimiter };
