# Roadmap

The project remains **read-only toward CUCM** in every release.

## v1.1 – publication and CSS-aware analysis

- CSS-aware route-plan scope using `callingsearchspace` and `callingsearchspacemember`.
- CSS membership tab and CSS discovery during Test Connection.
- Correct HTTP 503 retry/backoff behavior without schema switching.
- Public-safe diagnostic mode.
- Production TLS guidance, release checksums and third-party notices.

## v1.2 – find and reclaim numbers

- **Find a free block** – return the next N free numbers, optionally requiring a consecutive block.
- **Reclaimable numbers** – identify DNs that exist but have no device attached, with a separate review status.
- Optional cross-cluster duplicate report.

## v1.3 – additional number ownership signals

- **Unity Connection check** – flag numbers that still own a mailbox using read-only CUPI REST access.
- **DID awareness** – correlate external phone number masks/translations with extension use where feasible.
- Range usage view by cluster/block.

## Later

- Shared reservation list so administrators do not assign the same candidate concurrently.
- Command-line mode with JSON output for automation/ITSM workflows.
- Saved searches and optional Windows Credential Manager integration.
- Additional tested CUCM release profiles after lab/community validation.

## Separate companion project

Webex Calling number lookup is planned as a separate tool rather than mixing cloud API logic into the CUCM AXL application.
