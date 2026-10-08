# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-07

First public release under the **DN Scout** name, with CSS-aware analysis.

### Added
- Public identity standardized as **DN Scout** (application, source entry point, executable, GitHub workflows, and documentation).
- Optional **Target CSS** selection. The application reads `callingsearchspace` / `callingsearchspacemember` and evaluates route-plan conflicts against partitions reachable through the selected Calling Search Space.
- **CSS Scope** results tab showing selected CSS membership and partition order.
- CSS discovery during **Test Connection**.
- `AXLDiag --public` mode for safer public issue sharing; public mode redacts common identifying fields and suppresses SQL/AXL response bodies.
- Configurable AXL retry controls: `axl_retry_attempts` and `axl_retry_base_seconds`.
- `THIRD_PARTY_NOTICES.md`, release SHA-256 generation and publication guidance.
- Offline tests for CSS scope, null/empty-CSS behavior, SQL literal escaping, diagnostic redaction and HTTP 503 behavior.

### Changed
- Minimum Python version is now documented correctly as **3.10+**.
- Read-only AXL prerequisites now document both **Standard AXL API Users** and **Standard AXL Read Only API Access**.
- TLS verification is labeled and documented as recommended for production.
- Saved credential wording now states that the optional password is stored **encrypted with Windows DPAPI**, rather than claiming that passwords are never stored.
- Compatibility claims are limited to CUCM releases actually validated by the project.

### Fixed
- HTTP **503** no longer triggers an AXL schema switch. It is retried with backoff as a service-unavailable/throttling condition.
- HTTP **599** remains the primary unsupported-schema signal for the one-time schema fallback.

## [1.0.0] - 2026-09-24

First public release.

### Added
- Availability search across 1–6 CUCM clusters, defined in `cucm_clusters.json` with neutral IDs (`CL1`, `CL2`, …) and optional friendly names.
- Multi-select cluster picker (All / CL1 / CL2 / CL3 …) and a status badge per cluster showing the CUCM version after Test Connection.
- Status per number: USED, OTHER PT, CHECK (wildcard coverage, interdigit overlap, CFA/CFB/CFNA/CFUR target) and FREE, with a per-cluster column.
- Tabs for DNs (with devices), route patterns, translation patterns, other route-plan entries, wildcard coverage, Call Forward All and Busy / No Answer / Unregistered destinations.
- Status filter chips with counts, text filter, detail pane with every reason for the selected number, CSV export of the current tab.
- Windows 11 style light and dark themes (sv-ttk), sharp text on scaled displays.
- Optional **Remember me**: username and password saved in `cucm_clusters.json`, with the password encrypted by Windows DPAPI for the current Windows user (never plain text). Team builds strip saved credentials.
- `axl_diag.py`: layer-by-layer AXL troubleshooting tool (proxy, TCP, TLS, auth, AXL version, and a replay of the app's own queries).
- `build_exe.bat`: builds portable Windows executables with PyInstaller.
- Offline test suite (`tests/`), CI on Windows, and an automated release workflow that builds and publishes the executables when a version tag is pushed.

### Fixed (during pre-release testing)
- HTTP 599 (unsupported AXL version) was reported as "AXL is busy/throttled".
- A short `axl_version` such as `14` is now sent as `14.0`; if a cluster rejects the version, the other schema is tried automatically.
- The progress bar kept a filled block after a job finished.
- Test Connection now reports every cluster instead of stopping at the first failure.
