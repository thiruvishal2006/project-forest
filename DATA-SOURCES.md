# USB identification data

`usb.ids` is a snapshot from the [USB ID Repository](https://usb-ids.gowdy.us/usb.ids), a volunteer-maintained database used to map USB vendor and product IDs to human-readable descriptions.

- Snapshot bundled: version `2026.06.26` (downloaded September 25, 2026)
- License stated by the repository: GPL version 2 or later **or** 3-clause BSD
- Contents used here: vendor and product identifiers/names only
- Not included: threat intelligence, device trust judgments, or a device-specific class mapping
- Refresh: run `npm run update-usb-ids` from this repository; restart the server to load the replaced snapshot

The lookup is identification evidence only. A listed ID does not mean the physical device is authentic, trusted, or safe. An unlisted ID is treated as uncertainty, not as evidence of maliciousness. The updater downloads bounded HTTP ranges, checks each range and the final snapshot header/version, then atomically replaces the existing file so an interrupted update does not destroy the prior snapshot.
