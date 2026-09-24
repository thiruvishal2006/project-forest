const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'usb-analyzer-'));
process.env.DATABASE_PATH = path.join(tempDir, 'test.sqlite');
process.env.REANALYZE_TOKEN = 'test-only-admin-token-1234567890';
process.env.API_RATE_LIMIT_MAX = '1000';
process.env.ANALYSIS_RATE_LIMIT_MAX = '1000';
const { app } = require('../server');
const { createRateLimiter } = require('../server');
const database = require('../db');
const { analyzeDevice, loadPolicy } = require('../risk-engine');
const { lookupUsbDevice, normalizeUsbId } = require('../usb-intelligence');
let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  database.close();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function request(route, options) {
  const response = await fetch(`${baseUrl}${route}`, options);
  return { response, body: await response.json() };
}

async function analyze(payload) {
  return request('/api/analyze', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload)
  });
}

test('exposes API health and security headers without serving a frontend', async () => {
  const { body } = await request('/health');
  assert.deepEqual(body, { success: true, data: { status: 'ok' } });
  assert.deepEqual((await request('/api/health')).body, body);
  const health = await fetch(`${baseUrl}/health`);
  assert.equal(health.headers.get('content-security-policy')?.includes("default-src 'self'"), true);
  assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(health.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.equal(health.headers.get('strict-transport-security'), null);
  assert.equal((await fetch(`${baseUrl}/`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/CSS/style.css`)).status, 404);
});

test('normalizes VID/PID with optional prefix and case', () => {
  for (const value of ['0x0781', '0781', '0X0781', '0781']) assert.equal(normalizeUsbId(value), '0781');
  assert.equal(normalizeUsbId('0xZZZZ'), null);
  assert.equal(normalizeUsbId('12345'), null);
});

test('looks up known vendor and product descriptions for all three sample devices', () => {
  const digispark = lookupUsbDevice('0x16D0', '0x0753');
  assert.equal(digispark.vendor, 'MCS');
  assert.equal(digispark.product, 'Digistump DigiSpark');
  assert.equal(digispark.known, true);
  assert.equal(lookupUsbDevice('0x413C', '0x2107').product, 'KB212-B Quiet Key Keyboard');
  assert.equal(lookupUsbDevice('0x0781', '0x5567').product, 'Cruzer Blade');
});

test('continues safely when the local USB snapshot is unavailable', () => {
  const unavailable = analyzeDevice({
    deviceName: 'USB device', vendorId: 'FFFF', productId: '0001', serial: ''
  }, { lookup: () => ({
    vendorId: 'FFFF', productId: '0001', vendor: null, product: null,
    knownVendor: false, knownProduct: false, known: false,
    databaseAvailable: false, databaseVersion: null, source: null
  }) });
  assert.equal(unavailable.riskScore, 15);
  assert.ok(unavailable.riskFactors.some((factor) => factor.code === 'lookup_unavailable'));
  assert.ok(!unavailable.riskFactors.some((factor) => factor.code === 'unknown_vendor'));
});

test('sample device assessments use per-device evidence instead of one generic score', () => {
  const samples = [
    { deviceName: 'Digispark ATTINY85', vendorId: '0x16D0', productId: '0x0753', serial: '3' },
    { deviceName: 'Standard Dell USB Keyboard', vendorId: '0x413C', productId: '0x2107', serial: '2' },
    { deviceName: 'Demo USB', vendorId: '0x0781', productId: '0x5567', serial: 'SN-LOCAL-1' }
  ].map((input) => analyzeDevice(input));
  assert.deepEqual(samples.map((result) => result.riskScore), [10, 10, 15]);
  assert.notEqual(samples[0].riskFactors.find((factor) => factor.code === 'recognized_pair').reason,
    samples[1].riskFactors.find((factor) => factor.code === 'recognized_pair').reason);
  assert.ok(samples[0].riskFactors.some((factor) => factor.code === 'name_consistent'));
  assert.ok(samples[1].riskFactors.some((factor) => factor.code === 'name_consistent'));
  assert.ok(samples[2].riskFactors.some((factor) => factor.code === 'name_mismatch' && factor.impact === 5));
  assert.ok(samples.every((result) => !/malicious/i.test(result.verdict)));
});

test('calculates unknown VID, known vendor with unknown PID, absent serial, class exposure and trust policy distinctly', () => {
  const base = { deviceName: 'Test device', vendorId: '0x413C', productId: '0x2107', serial: 'S1' };
  const unknownVendor = analyzeDevice({ ...base, vendorId: '0xFFFF', productId: '0x0001' });
  assert.ok(unknownVendor.riskFactors.some((factor) => factor.code === 'unknown_vendor' && factor.impact === 15));
  const unknownProduct = analyzeDevice({ ...base, productId: '0xFFFF' });
  assert.ok(unknownProduct.riskFactors.some((factor) => factor.code === 'unknown_product' && factor.impact === 10));
  const missingSerial = analyzeDevice({ ...base, serial: '' });
  assert.ok(missingSerial.riskFactors.some((factor) => factor.code === 'missing_serial' && factor.impact === 5));
  const composite = analyzeDevice({ ...base, deviceClass: 'composite' });
  assert.ok(composite.riskFactors.some((factor) => factor.code === 'device_class_surface' && factor.impact === 8));
  const policy = { ...loadPolicy(), trustedDevices: ['413C:2107'] };
  const trusted = analyzeDevice(base, { policy });
  assert.ok(trusted.riskFactors.some((factor) => factor.code === 'policy_trusted' && factor.impact === -10));
  assert.equal(trusted.riskScore, 5);
});

test('normalizes API inputs and returns explainable identification and score data', async () => {
  const upper = await analyze({ deviceName: 'Cruzer Blade', vendorId: '0X0781', productId: '5567', serial: 'SN1' });
  const lower = await analyze({ deviceName: 'Cruzer Blade', vendorId: '0781', productId: '0x5567', serial: 'SN2' });
  assert.equal(upper.response.status, 201);
  assert.equal(upper.body.success, true);
  assert.equal(upper.body.data.vendorId, '0781');
  assert.equal(upper.body.data.productId, '5567');
  assert.equal(upper.body.data.riskScore, 10);
  assert.equal(upper.body.data.analysisVersion, 2);
  assert.equal(upper.body.data.serialPresent, true);
  assert.equal(Object.hasOwn(upper.body.data, 'serial'), false);
  assert.equal(JSON.stringify(upper.body).includes('SN1'), false);
  assert.equal(database.getDevice(upper.body.data.id).serial, 'provided');
  assert.equal(upper.body.data.device.vendor, 'SanDisk Corp.');
  assert.equal(upper.body.data.device.product, 'Cruzer Blade');
  assert.deepEqual(upper.body.data.risk_factors, upper.body.data.riskFactors);
  assert.ok(upper.body.data.riskFactors.some((factor) => factor.code === 'name_consistent'));
  assert.equal(lower.body.data.riskScore, upper.body.data.riskScore);
});

test('rejects invalid VID, invalid PID, malformed payloads, oversized input and long fields', async () => {
  const cases = [
    [{ deviceName: 'USB', vendorId: 'nope', productId: '0001' }, 400],
    [{ deviceName: 'USB', vendorId: '0781', productId: 'xyz' }, 400],
    [{ deviceName: 'x'.repeat(121), vendorId: '0781', productId: '0001' }, 400],
    [{ deviceName: 'USB', vendorId: '0781', productId: '0001', deviceClass: 'arbitrary' }, 400],
    [[], 400]
  ];
  for (const [payload, expectedStatus] of cases) {
    const { response, body } = await analyze(payload);
    assert.equal(response.status, expectedStatus);
    assert.equal(body.success, false);
    assert.equal(typeof body.message, 'string');
  }
  const oversized = await fetch(`${baseUrl}/api/analyze`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deviceName: 'x'.repeat(40000), vendorId: '0781', productId: '0001' })
  });
  assert.equal(oversized.status, 413);
  assert.equal((await oversized.json()).success, false);
  const invalidJson = await fetch(`${baseUrl}/api/analyze`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{'
  });
  assert.equal(invalidJson.status, 400);
});

test('keeps duplicate scans public, paginated, and does not disclose submitted serial values', async () => {
  const payload = { deviceName: 'Cruzer Blade', vendorId: '0781', productId: '5567', serial: 'SN-DUP' };
  const first = await analyze(payload);
  const second = await analyze(payload);
  assert.notEqual(first.body.data.id, second.body.data.id);
  const listed = await request('/api/devices');
  assert.ok(listed.body.data.some((row) => row.id === first.body.data.id));
  assert.equal(listed.body.data.some((row) => Object.hasOwn(row, 'serial')), false);
  assert.equal(JSON.stringify(listed.body).includes('SN-DUP'), false);
  const page = await request('/api/devices?page=1&limit=1');
  assert.equal(page.response.status, 200);
  assert.equal(page.body.data.length, 1);
  assert.equal(page.response.headers.get('x-page-size'), '1');
  assert.equal((await request('/api/devices?limit=1000')).response.status, 400);
  assert.equal((await request('/api/devices?sort=serial')).response.status, 400);
  const report = await request(`/api/reports/${first.body.data.id}`);
  assert.equal(report.body.data.riskScore, first.body.data.riskScore);
  assert.equal(Object.hasOwn(report.body.data, 'serial'), false);
  assert.equal(report.body.data.device.product, 'Cruzer Blade');
  assert.ok(Array.isArray(report.body.data.riskFactors));
});

test('preserves old score rows and supports explicit in-place reanalysis', async () => {
  const inserted = database.insertDevice.run({
    deviceName: 'Demo USB', vendorId: '0x0781', productId: '0x5567', serial: 'SN-OLD',
    riskScore: 15, verdict: 'Low Risk', factors: JSON.stringify(['Identifiers are well-formed and a serial number is present.']),
    scannedAt: new Date().toISOString()
  });
  const id = Number(inserted.lastInsertRowid);
  const before = await request(`/api/reports/${id}`);
  assert.equal(before.body.data.riskScore, 15);
  assert.equal(before.body.data.legacy, true);
  assert.equal((await request(`/api/devices/${id}/reanalyze`, { method: 'POST' })).response.status, 401);
  assert.equal((await request(`/api/devices/${id}/reanalyze`, { method: 'POST', headers: { authorization: 'Bearer wrong-token-xxxxxxxx' } })).response.status, 401);
  const reanalyzed = await request(`/api/devices/${id}/reanalyze`, { method: 'POST', headers: { authorization: `Bearer ${process.env.REANALYZE_TOKEN}` } });
  assert.equal(reanalyzed.response.status, 200);
  assert.equal(reanalyzed.body.data.id, id);
  assert.equal(reanalyzed.body.data.analysisVersion, 2);
  assert.equal(reanalyzed.body.data.riskScore, 15);
  assert.equal(reanalyzed.body.data.device.product, 'Cruzer Blade');
  const after = await request(`/api/reports/${id}`);
  assert.equal(after.body.data.analysisVersion, 2);
});

test('handles missing reports and unknown API endpoints with JSON errors', async () => {
  const missing = await request('/api/reports/999999');
  assert.equal(missing.response.status, 404);
  assert.equal(missing.body.success, false);
  const invalidId = await request('/api/devices/nope/reanalyze', { method: 'POST' });
  assert.equal(invalidId.response.status, 401);
  const unknown = await request('/api/not-a-route');
  assert.equal(unknown.response.status, 404);
  assert.equal(unknown.body.success, false);
  for (const route of ['/.env', '/data/usb-risk-analyzer.sqlite', '/usb.ids', '/config/risk-policy.json', '/.git/config', '/admin', '/debug', '/metrics']) {
    const hidden = await fetch(`${baseUrl}${route}`);
    assert.equal(hidden.status, 404, route);
    assert.equal((await hidden.text()).includes('JWT_SECRET'), false);
  }
  const wrongMethod = await fetch(`${baseUrl}/api/analyze`, { method: 'GET' });
  assert.equal(wrongMethod.status, 405);
});

test('SQL, HTML and shell metacharacters remain inert input data', async () => {
  for (const deviceName of ["x'); DROP TABLE devices;--", '<img src=x onerror=alert(1)>', 'USB; & whoami | `cmd`']) {
    const { response, body } = await analyze({ deviceName, vendorId: '0781', productId: '5567' });
    assert.equal(response.status, 201);
    assert.equal(body.data.deviceName, deviceName);
  }
  assert.equal((await request('/api/devices')).response.status, 200);
  assert.equal((await analyze({ deviceName: 'x', vendorId: "0781' OR 1=1--", productId: '5567' })).response.status, 400);
  assert.equal((await analyze({ deviceName: '../../.env', vendorId: '0781', productId: '5567' })).response.status, 201);
});

test('rate limiter returns safe 429 response and standard rate limit headers', async () => {
  const express = require('express');
  const limited = express();
  limited.get('/', createRateLimiter(1, 'test', 60000), (_req, res) => res.json({ ok: true }));
  const tempServer = limited.listen(0);
  await new Promise((resolve) => tempServer.once('listening', resolve));
  const url = `http://127.0.0.1:${tempServer.address().port}/`;
  try {
    assert.equal((await fetch(url)).status, 200);
    const limitedResponse = await fetch(url);
    assert.equal(limitedResponse.status, 429);
    assert.equal((await limitedResponse.json()).message, 'Too many requests. Try again later.');
    assert.ok(limitedResponse.headers.get('ratelimit'));
  } finally { await new Promise((resolve) => tempServer.close(resolve)); }
});

test('service source has no frontend coupling or unsafe SQL interpolation', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.doesNotMatch(source, /FRONTEND|express\.static/);
  const databaseSource = fs.readFileSync(path.join(__dirname, '..', 'db.js'), 'utf8');
  assert.match(databaseSource, /WHERE id = \?/);
  assert.match(databaseSource, /LIMIT \? OFFSET \?/);
});
