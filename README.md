# USB Risk Analyzer Backend

Standalone Node.js API for USB device identification and risk screening. This repository contains the working Express service, SQLite layer, scoring engine, USB identification snapshot, security controls, and automated tests. It does not contain or serve the browser frontend.

## Stack and request flow

- **Runtime/API:** Node.js and Express (`server.js`).
- **Validation/security:** request validation, Helmet headers, bounded JSON and URL sizes, same-origin deployment, and configurable rate limits in `server.js`.
- **Analysis:** `risk-engine.js` applies the policy in `config/risk-policy.json`; it receives normalized user input and an identification result from `usb-intelligence.js`.
- **USB data:** `usb-intelligence.js` reads the bundled `usb.ids` snapshot into memory and resolves VID/PID labels. It does not perform threat intelligence or claim that a recognized device is safe.
- **Persistence:** `db.js` uses `better-sqlite3` prepared statements and initializes `schema.sql` automatically. New serial input is reduced to a presence marker before storage.
- **Response:** the API serializes score, factors, identification, and timestamp. Serial values are never returned.

The existing browser frontend calls `POST /api/analyze`, `GET /api/devices`, and `GET /api/reports/:id`. Those routes are retained. The server is intentionally API-only here; the frontend can be hosted separately and configured to call this API through the same origin/reverse proxy. No frontend source is required at runtime.

## Requirements and local setup

Use Node.js 20 or newer and npm. From this repository directory:

```powershell
npm ci
Copy-Item .env.example .env
```

Edit `.env` if needed. `REANALYZE_TOKEN` is optional; when set, replace the example value with a unique random secret of at least 32 characters. Generate one with:

```powershell
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Start the API and run tests:

```powershell
npm start
npm test
```

The service listens on `http://localhost:5000` by default. The SQLite database is created automatically under `data/` on first startup. See [API.md](API.md), [DATABASE.md](DATABASE.md), and [SECURITY.md](SECURITY.md).

## Risk interpretation

Scores are explainable screening estimates based on identifier coverage, provided name consistency, serial presence, device class, and optional local policy. They are not malware detection, authenticity verification, or proof that hardware is safe or malicious. See the factor explanations in each API response.

## USB ID data

The bundled snapshot source, version, dual-license notice, update method, and limits are documented in [DATA-SOURCES.md](DATA-SOURCES.md). The snapshot is identification data only. Refresh it with `npm run update-usb-ids` and restart the server to load the updated file.

## Repository notes

- The application has no user accounts: scans and reports are shared and public to API clients.
- Existing local databases are not included. SQLite files, `.env`, and `node_modules` are ignored by Git.
- A project license has not been selected. The USB ID snapshot retains its own upstream licensing notice; that does not license this application. Choose and add a project license before public redistribution if required.

Contributions should follow [CONTRIBUTING.md](CONTRIBUTING.md).
