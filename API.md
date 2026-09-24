# API Reference

All responses use `{ "success": true, "data": ... }` or `{ "success": false, "message": "..." }`. JSON request bodies must use `Content-Type: application/json`. No user account is required; analyses and reports are shared public records.

## `GET /health` and `GET /api/health`

Returns minimal process health:

```json
{"success":true,"data":{"status":"ok"}}
```

## `POST /api/analyze`

Validates a device, scores it, saves the result, and returns HTTP 201.

Request:

```json
{
  "deviceName": "Cruzer Blade",
  "vendorId": "0x0781",
  "productId": "0x5567",
  "serial": "optional-user-input",
  "deviceClass": "mass_storage"
}
```

`deviceName` is required (maximum 120 characters); `vendorId` and `productId` are required 16-bit hexadecimal IDs (maximum 32 input characters each); `serial` is optional text (maximum 128 characters); `deviceClass` is optional and one of `unknown`, `hid`, `mass_storage`, `composite`, or `other`.

The response includes `id`, normalized IDs, `serialPresent` (boolean), `riskScore` (0–100), `verdict`, `riskFactors`, `scoreBreakdown`, `device`, `identification`, `analysisVersion`, `dataSource`, and `scannedAt`. It does not include the supplied serial text.

## `GET /api/devices?page=1&limit=50`

Lists shared scan records, newest first. `page` is 1–1,000,000; `limit` is 1–100 and defaults to 50. Unknown query parameters are rejected. Response data is an array of report objects; `X-Page` and `X-Page-Size` indicate the returned page. Serial values are not returned.

## `GET /api/reports/:id`

Returns the saved analysis identified by a positive integer ID. Unknown IDs return 404. Serial values are not returned.

## `POST /api/devices/:id/reanalyze`

Administrative compatibility endpoint for recalculating a saved row using the current scoring model. Disabled (404) unless `REANALYZE_TOKEN` is configured. When enabled, pass `Authorization: Bearer <REANALYZE_TOKEN>`. Do not put the token in browser code. This route shares the analysis rate limit.

## Errors and limits

Validation errors return 400, malformed JSON returns 400, oversized JSON returns 413, throttled requests return 429, and unknown API routes return 404. Error responses contain safe messages and no stack traces. The default JSON body cap is 32 KiB. See environment settings in [SECURITY.md](SECURITY.md).
