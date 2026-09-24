const fs = require('node:fs');
const path = require('node:path');
const { lookupUsbDevice, normalizeUsbId, nameMatchesProduct, SOURCE_URL } = require('./usb-intelligence');

const POLICY_PATH = path.join(__dirname, 'config', 'risk-policy.json');

function loadPolicy() {
  const policy = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  if (!Number.isFinite(policy.baseScore) || !Array.isArray(policy.thresholds) || !Array.isArray(policy.trustedDevices)) {
    throw new Error('Risk policy is missing required settings.');
  }
  return policy;
}

const policy = loadPolicy();

function getVerdict(score, thresholds = policy.thresholds) {
  return thresholds.find((range) => score >= range.min && score <= range.max)?.verdict || 'Unclassified';
}

function analyzeDevice(input, options = {}) {
  const activePolicy = options.policy || policy;
  const lookup = (options.lookup || lookupUsbDevice)(input.vendorId, input.productId);
  const device = {
    name: input.deviceName,
    vid: lookup.vendorId || String(input.vendorId),
    pid: lookup.productId || String(input.productId),
    vendor: lookup.vendor,
    product: lookup.product,
    deviceClass: input.deviceClass || 'unknown'
  };
  const factors = [{
    code: 'baseline',
    factor: 'Baseline uncertainty',
    impact: activePolicy.baseScore,
    reason: 'Every new analysis starts from the configured baseline; this is a screening score, not a finding of malicious behavior.'
  }];
  let score = activePolicy.baseScore;

  if (!lookup.databaseAvailable) {
    factors.push({ code: 'lookup_unavailable', factor: 'Device ID lookup unavailable', impact: 0,
      reason: 'The local USB ID snapshot could not be loaded. No vendor or product reputation was inferred.' });
  } else if (!lookup.knownVendor) {
    const impact = activePolicy.weights.unknownVendor;
    score += impact;
    factors.push({ code: 'unknown_vendor', factor: 'Vendor not listed', impact,
      reason: `VID ${lookup.vendorId || input.vendorId} was not found in the local USB ID Repository snapshot. This is uncertainty, not evidence of maliciousness.` });
  } else if (!lookup.knownProduct) {
    const impact = activePolicy.weights.unknownProduct;
    score += impact;
    factors.push({ code: 'unknown_product', factor: 'Product not listed', impact,
      reason: `VID ${lookup.vendorId || input.vendorId} maps to ${lookup.vendor}, but PID ${lookup.productId || input.productId} has no product entry in the local snapshot.` });
  } else {
    factors.push({ code: 'recognized_pair', factor: 'VID/PID identification', impact: 0,
      reason: `The snapshot identifies ${lookup.vendor} — ${lookup.product}. Identification does not mean the device is trusted or safe.` });
    if (nameMatchesProduct(input.deviceName, lookup.product)) {
      factors.push({ code: 'name_consistent', factor: 'Reported name consistency', impact: 0,
        reason: 'The entered device name shares a meaningful term with the product label in the USB ID snapshot.' });
    } else {
      const impact = activePolicy.weights.nameMismatch;
      score += impact;
      factors.push({ code: 'name_mismatch', factor: 'Reported name differs from product label', impact,
        reason: `The entered name does not match the listed product “${lookup.product}”. This may be a generic or mistaken label; it is not proof of spoofing.` });
    }
  }

  if (!input.serial) {
    const impact = activePolicy.weights.missingSerial;
    score += impact;
    factors.push({ code: 'missing_serial', factor: 'Serial number missing', impact,
      reason: 'Without a serial number, this device instance is harder to distinguish from another with the same IDs.' });
  } else {
    factors.push({ code: 'serial_present', factor: 'Serial number provided', impact: 0,
      reason: 'A serial number was supplied. Its authenticity has not been independently verified.' });
  }

  const deviceClass = input.deviceClass || 'unknown';
  const classImpact = activePolicy.weights.deviceClass?.[deviceClass] ?? 0;
  if (classImpact !== 0) {
    score += classImpact;
    factors.push({ code: 'device_class_surface', factor: `${deviceClass.replace('_', ' ')} attack surface`, impact: classImpact,
      reason: `The selected ${deviceClass.replace('_', ' ')} class has capabilities that can be abused. This characteristic alone does not mean the device is malicious.` });
  } else if (deviceClass === 'unknown') {
    factors.push({ code: 'class_not_supplied', factor: 'Device class not supplied', impact: 0,
      reason: 'The ID repository does not map a USB class to this VID/PID, and the form did not provide one; no class risk was inferred.' });
  }

  const canonicalPair = `${lookup.vendorId}:${lookup.productId}`;
  if (activePolicy.trustedDevices.includes(canonicalPair)) {
    const impact = activePolicy.weights.trustedDevice;
    score += impact;
    factors.push({ code: 'policy_trusted', factor: 'Locally trusted device', impact,
      reason: 'This VID/PID is explicitly allowlisted in risk-policy.json. A local allowlist is policy, not external security proof.' });
  }

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));
  return {
    analysisVersion: 2,
    device,
    identification: lookup,
    riskFactors: factors,
    scoreBreakdown: { baseScore: activePolicy.baseScore, unboundedScore: score, finalScore },
    riskScore: finalScore,
    verdict: getVerdict(finalScore, activePolicy.thresholds),
    dataSource: { name: 'USB ID Repository', version: lookup.databaseVersion, url: SOURCE_URL }
  };
}

function legacyAnalysis(row) {
  let previousFactors = [];
  try { previousFactors = JSON.parse(row.factors); } catch { /* preserve and label unreadable legacy evidence */ }
  const factors = Array.isArray(previousFactors)
    ? previousFactors.map((reason) => ({ code: 'legacy', factor: 'Legacy analysis explanation', impact: 0, reason: String(reason) }))
    : [{ code: 'legacy', factor: 'Legacy analysis', impact: 0, reason: 'The previous explanation could not be decoded.' }];
  return {
    analysisVersion: 1,
    legacy: true,
    riskFactors: factors,
    scoreBreakdown: null,
    device: { name: row.deviceName, vid: row.vendorId, pid: row.productId, vendor: null, product: null, deviceClass: 'unknown' },
    dataSource: null
  };
}

function decodeAnalysis(row) {
  try {
    const analysis = JSON.parse(row.factors);
    if (analysis && !Array.isArray(analysis) && analysis.analysisVersion >= 2) return { ...analysis, legacy: false };
  } catch { /* return a legacy marker below */ }
  return legacyAnalysis(row);
}

function calculateForSavedDevice(row) {
  const existing = decodeAnalysis(row);
  return analyzeDevice({
    deviceName: row.deviceName,
    vendorId: normalizeUsbId(row.vendorId) || row.vendorId,
    productId: normalizeUsbId(row.productId) || row.productId,
    serial: row.serial,
    deviceClass: existing.device?.deviceClass || 'unknown'
  });
}

module.exports = { analyzeDevice, calculateForSavedDevice, decodeAnalysis, getVerdict, loadPolicy };
