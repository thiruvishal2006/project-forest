# Security and public access

The analyzer is intentionally anonymous: anyone who can reach the site can submit a scan and read the shared scan history and reports. The application has no accounts, cookies, sessions, or user-specific authorization. Scan results are public data; do not enter confidential names or identifiers. A submitted serial is used only while scoring and is stored as a presence marker, never returned by the API. Older database records may still contain their historical serial values on disk, but API serialization does not expose them.

## Exposed endpoints

- `GET /health`, `GET /api/health`: minimal service status.
- `POST /api/analyze`: validates and stores a public scan. Analysis is rate limited.
- `GET /api/devices?page=1&limit=50`: public, bounded, paginated scan history.
- `GET /api/reports/:id`: public report lookup.
- `POST /api/devices/:id/reanalyze`: administrative maintenance action. It returns 404 when `REANALYZE_TOKEN` is unset and otherwise requires `Authorization: Bearer <token>`; it is rate limited. The public UI does not expose it.
- This backend-only repository serves no static files or frontend application. Unknown paths return 404. Database files and dotfiles are never served by Express.

All SQL values use prepared statements. User strings are displayed in the browser using `textContent`; the server does not execute shell commands from request data. API errors are generic and do not include stack traces or database contents. JSON input, field lengths, URL lengths, pagination, and per-IP request rates have limits.

## Configuration

Copy `.env.example` to the repository root `.env`, then replace its example `REANALYZE_TOKEN` with a cryptographically random secret for the maintenance endpoint. Startup rejects short or obvious placeholder values. Never commit `.env`. Available server settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `5000` | Listen port |
| `HOST` | `0.0.0.0` | Listen address |
| `DATABASE_PATH` | `data/usb-risk-analyzer.sqlite` | SQLite file path |
| `NODE_ENV` | `development` | Use `production` when deployed |
| `TRUST_PROXY` | `0` | Number of trusted proxy hops; keep `0` unless requests arrive only through a known proxy |
| `API_RATE_LIMIT_WINDOW_MS` | `60000` | API request window in milliseconds |
| `API_RATE_LIMIT_MAX` | `120` | API requests per client per window |
| `ANALYSIS_RATE_LIMIT_MAX` | `30` | Analysis and maintenance requests per client per window |
| `MAX_REQUEST_SIZE_BYTES` | `32768` | Maximum JSON body size |
| `REANALYZE_TOKEN` | unset | Secret for the maintenance endpoint; route disabled when unset |

Rate limits use the process-local memory store. For multiple server replicas, configure a shared rate-limit store before scaling; otherwise each replica enforces an independent quota.

## Production deployment

Run `npm start` with `NODE_ENV=production` behind a TLS reverse proxy. Restrict network access so clients cannot bypass the proxy and reach the HTTP application directly. Set `TRUST_PROXY` to the exact trusted proxy hop count only after that network boundary is enforced; the default is zero. HSTS is sent only for production requests Express recognizes as HTTPS. The site and API are same-origin, with no credentialed cross-origin access and no cookie-based authentication, so there is no cross-site request forgery token flow.

This is a small public demo service, not an abuse-proof anonymous platform: rate limits are per IP and can be shared by NAT users or evaded across addresses. Use a shared rate-limit store, monitoring, backups, and an operational retention policy before exposing it to substantial traffic.
