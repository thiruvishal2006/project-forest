const fs = require('node:fs');
const path = require('node:path');

const DATA_PATH = path.join(__dirname, 'usb.ids');
const SOURCE_URL = 'https://usb-ids.gowdy.us/usb.ids';
const STOP_WORDS = new Set(['usb', 'device', 'standard', 'the', 'corp', 'corporation', 'inc', 'ltd', 'co']);

function normalizeUsbId(value) {
  if (typeof value !== 'string') return null;
  const raw = value.trim().replace(/^0x/i, '');
  return /^[0-9a-f]{1,4}$/i.test(raw) ? raw.toUpperCase().padStart(4, '0') : null;
}

function parseUsbIds(text) {
  const vendors = new Map();
  let currentVendor = null;
  for (const line of text.split(/\r?\n/)) {
    const vendorMatch = /^([0-9a-fA-F]{4})\s{2,}(.+?)\s*$/.exec(line);
    if (vendorMatch) {
      currentVendor = vendorMatch[1].toUpperCase();
      vendors.set(currentVendor, { name: vendorMatch[2].trim(), products: new Map() });
      continue;
    }
    const productMatch = /^\s+([0-9a-fA-F]{4})\s{2,}(.+?)\s*$/.exec(line);
    if (productMatch && currentVendor) {
      vendors.get(currentVendor).products.set(productMatch[1].toUpperCase(), productMatch[2].trim());
      continue;
    }
    if (line && !/^\s/.test(line) && !line.startsWith('#')) currentVendor = null;
  }
  return vendors;
}

function readSnapshot() {
  try {
    const text = fs.readFileSync(DATA_PATH, 'utf8');
    const match = /^# Version:\s*(.+)$/m.exec(text);
    return { vendors: parseUsbIds(text), version: match?.[1]?.trim() || 'unknown', available: true };
  } catch {
    return { vendors: new Map(), version: null, available: false };
  }
}

const snapshot = readSnapshot();

function lookupUsbDevice(vendorId, productId) {
  const vid = normalizeUsbId(vendorId);
  const pid = normalizeUsbId(productId);
  const vendor = vid ? snapshot.vendors.get(vid) : undefined;
  const product = vendor && pid ? vendor.products.get(pid) : undefined;
  return {
    vendorId: vid,
    productId: pid,
    vendor: vendor?.name || null,
    product: product || null,
    knownVendor: Boolean(vendor),
    knownProduct: Boolean(product),
    known: Boolean(vendor && product),
    deviceClass: null,
    databaseAvailable: snapshot.available,
    databaseVersion: snapshot.version,
    source: SOURCE_URL
  };
}

function nameMatchesProduct(deviceName, productName) {
  if (!deviceName || !productName) return false;
  const tokens = (value) => value.toLowerCase().match(/[a-z0-9]+/g) || [];
  const productTokens = new Set(tokens(productName).filter((token) => token.length >= 3 && !STOP_WORDS.has(token)));
  return tokens(deviceName).some((token) => token.length >= 3 && !STOP_WORDS.has(token) && productTokens.has(token));
}

module.exports = { lookupUsbDevice, normalizeUsbId, nameMatchesProduct, parseUsbIds, SOURCE_URL };
