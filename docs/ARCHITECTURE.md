# Architecture and Security Model

## Purpose

DN Scout is a read-only administrative analysis tool for evaluating candidate numbers and their relationships to the CUCM dial plan across multiple Cisco Unified Communications Manager clusters.

It is intentionally narrow: collect relevant configuration data through AXL, evaluate number conflicts locally, and present the evidence behind each status. It does not configure CUCM and it is not a replacement for Cisco Unified CM Digit Analysis.

## Data flow

```text
Administrator workstation
        |
        | HTTPS :8443 / AXL
        v
+---------------------------+
| CUCM Publisher - Cluster 1|
+---------------------------+
        |
        | read-only AXL / SELECT
        v
route-plan / partition / CSS / device / forwarding data

Administrator workstation
        |
        +----> repeat for selected clusters (up to 6)
        |
        v
local candidate generator + wildcard/overlap evaluator
        |
        v
USED / OTHER PT / CHECK / FREE + evidence + CSV export
```

## CUCM operations

The main application uses:

- `getCCMVersion` to display the CUCM version during connection testing;
- `executeSQLQuery` with read-only `SELECT` statements.

The core SQL data sources include:

- `numplan`
- `routepartition`
- `typepatternusage`
- `devicenumplanmap`
- `device`
- `callforwarddynamic`
- `callingsearchspace`
- `callingsearchspacemember`

No INSERT, UPDATE, DELETE or configuration AXL methods are used by the application.

## Candidate generation

The user supplies a numeric prefix and total digit length. For example:

```text
prefix = 5405
digits = 6
```

generates candidates `540500` through `540599`, subject to the `max_candidates` safety limit.

## Pattern evaluation

Collected CUCM patterns are normalized and evaluated locally.

The matcher handles:

- `X`
- `!`
- `?`
- `+`
- bracket ranges such as `[2-9]`
- negated ranges such as `[^0-4]`
- dot delimiter
- shorter/longer digit overlaps

`@` numbering-plan patterns are identified but intentionally not evaluated because Cisco numbering-plan behavior is broader than the local matcher's scope.

Calling/called-party transformation patterns and templates are excluded from number consumption because they transform digits rather than own the destination number itself.

## Partition and CSS scope

### Partition

When a target partition is selected, an exact blocking pattern in that partition is treated as `USED`; an exact pattern in another partition is reported as `OTHER PT`.

### Calling Search Space

When a Target CSS is selected, the application reads the CSS's ordered membership from `callingsearchspace` and `callingsearchspacemember`.

A route-plan object is considered CSS-reachable when:

- its partition is a member of the selected CSS; or
- its partition is the CUCM null partition (`<None>`), which the application treats as globally reachable.

A conflict that exists only in a partition outside the selected CSS is surfaced as `OTHER PT` rather than silently treated as free.

Call-forward destinations remain `CHECK` regardless of selected CSS because forwarding destinations can use calling-search-space behavior associated with the forwarding source, and a single manually selected CSS does not prove that every forward is unreachable.

## Status semantics

| Status | Meaning |
|---|---|
| `USED` | Exact blocking route-plan object exists in the requested scope. |
| `OTHER PT` | A relevant route-plan conflict exists, but it is outside the requested Partition/CSS scope. |
| `CHECK` | Wildcard/interdigit overlap or forwarding destination needs review. |
| `FREE` | No condition detected by the implemented checks. |

The tool is intentionally conservative. `FREE` means the implemented checks did not find a conflict; it does not guarantee that every CUCM routing feature has been simulated.

## Authentication

Use a dedicated CUCM application user assigned to an Access Control Group with:

- `Standard AXL API Users`
- `Standard AXL Read Only API Access`

This aligns with Cisco's read-only AXL guidance for CUCM 11.5(1) and later.

## TLS

AXL traffic uses HTTPS on TCP 8443.

Production deployments should enable **Verify TLS certificate** and provide a trusted CUCM Tomcat CA/certificate bundle using the per-cluster `ca_bundle` setting.

TLS verification is not forced by default because many CUCM environments initially use private/self-signed PKI, but disabling verification weakens peer authentication.

## Credential storage

Credentials are normally kept only in application memory.

On Windows, optional **Remember me** stores:

- username in the local JSON configuration;
- password encrypted using Windows DPAPI for the current Windows user.

The public build never includes saved credentials, and the team build strips `saved_username` and `saved_password` when packaging the local cluster configuration.

## AXL availability handling

HTTP 503 is treated as service unavailable/throttling. The application retries with backoff and honors numeric `Retry-After` values.

HTTP 599 is treated as the unsupported-schema signal for the one-time common-schema fallback. A 503 response does not change the configured schema.

## Diagnostic privacy

`AXLDiag` has two modes:

- default/private mode: detailed troubleshooting, potentially sensitive;
- `--public`: redacts supplied host/user/prefix values, IPs and URL hosts, hides proxy values, suppresses SQL text and replaces AXL bodies with a size marker.

Even public-mode logs should be reviewed before posting.

## Known boundaries

The application does not claim to model all CUCM routing behavior. Examples outside the current scope include:

- complete Digit Analysis behavior;
- all composed line/device CSS combinations;
- time-of-day routing;
- local route groups and device-pool runtime behavior;
- every transformation or calling-party normalization chain;
- Unity Connection mailbox ownership;
- Webex Calling cloud number ownership;
- real-time registration state as an availability criterion.

These limitations are deliberate so the project remains understandable, read-only and testable.
