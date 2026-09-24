CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_name TEXT NOT NULL,
  vendor_id TEXT NOT NULL,
  product_id TEXT NOT NULL,
  serial TEXT NOT NULL DEFAULT '',
  risk_score INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  factors TEXT NOT NULL,
  scanned_at TEXT NOT NULL
);
