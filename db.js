const Database = require('better-sqlite3');
const fs = require('node:fs');
const path = require('node:path');

const configuredPath = process.env.DATABASE_PATH;
const dbPath = configuredPath
  ? (path.isAbsolute(configuredPath) ? configuredPath : path.resolve(__dirname, configuredPath))
  : path.join(__dirname, 'data', 'usb-risk-analyzer.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma('foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

const insertDevice = db.prepare(`INSERT INTO devices
  (device_name, vendor_id, product_id, serial, risk_score, verdict, factors, scanned_at)
  VALUES (@deviceName, @vendorId, @productId, @serial, @riskScore, @verdict, @factors, @scannedAt)`);
const updateDeviceAnalysis = db.prepare(`UPDATE devices SET
  vendor_id = @vendorId,
  product_id = @productId,
  risk_score = @riskScore,
  verdict = @verdict,
  factors = @factors
  WHERE id = @id`);
const deviceColumns = `id, device_name AS deviceName, vendor_id AS vendorId,
  product_id AS productId, serial, risk_score AS riskScore, verdict,
  scanned_at AS scannedAt`;

module.exports = {
  insertDevice,
  updateDeviceAnalysis,
  listDevices: (limit, offset) => db.prepare(`SELECT ${deviceColumns}, factors FROM devices ORDER BY id DESC LIMIT ? OFFSET ?`).all(limit, offset),
  getDevice: (id) => db.prepare(`SELECT ${deviceColumns}, factors FROM devices WHERE id = ?`).get(id),
  close: () => db.close()
};
