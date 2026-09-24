# Database

The backend uses SQLite through `better-sqlite3`. `db.js` creates the configured parent directory, enables foreign keys, and executes `schema.sql` at process startup. The default path is `data/usb-risk-analyzer.sqlite`; `DATABASE_PATH` can override it with an absolute path or a path relative to this repository.

## Schema

`devices` stores one row per analysis:

| Column | Type | Meaning |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | Report identifier |
| `device_name` | TEXT NOT NULL | User-provided display name |
| `vendor_id` | TEXT NOT NULL | Normalized four-digit VID |
| `product_id` | TEXT NOT NULL | Normalized four-digit PID |
| `serial` | TEXT NOT NULL DEFAULT '' | Empty or `provided`; new submissions never persist the serial itself |
| `risk_score` | INTEGER NOT NULL | Final bounded score from 0 to 100 |
| `verdict` | TEXT NOT NULL | Policy threshold label |
| `factors` | TEXT NOT NULL | JSON-serialized analysis explanation and identification |
| `scanned_at` | TEXT NOT NULL | ISO-8601 creation timestamp |

Statements with user-supplied values are parameterized. List reads are capped and paginated. Older databases may contain serial text from before serial minimization was added; APIs omit it, but operators should consider replacing or securely migrating legacy database files if at-rest removal is required.

## Backup and initialization

The database is initialized on startup, so no separate migration command is required for the initial schema. Stop writes or use SQLite’s online backup mechanism before copying a live database. Keep database and backup files out of source control and outside any static web root.
