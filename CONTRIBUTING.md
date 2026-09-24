# Contributing

## Development

1. Use Node.js 20 or newer.
2. Run `npm ci` and create a local `.env` from `.env.example`.
3. Run `npm test` before submitting changes.
4. Keep the backend API-only. Frontend code belongs in the separate web application repository.

## Implementation guidance

- Validate incoming values at the API boundary and use parameterized SQL.
- Render user-controlled strings as text in clients; do not introduce unsafe HTML construction.
- Keep error responses generic and avoid logging secrets, serial numbers, or complete request bodies.
- Add tests for behavior and security changes. Keep the risk factors explainable and do not label ID recognition as proof of trust or maliciousness.
- Do not commit `.env`, SQLite files, `node_modules`, or private scan data.

USB ID snapshot updates must retain the upstream notice and be described in `DATA-SOURCES.md`.
