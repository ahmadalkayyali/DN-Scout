# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability. Use GitHub **Security → Report a vulnerability** to create a private security advisory.

## Security design

- The application is read-only toward CUCM. It uses `getCCMVersion` and `executeSQLQuery` with `SELECT` statements; it does not send configuration write operations.
- Use a dedicated CUCM application user with **Standard AXL API Users** and **Standard AXL Read Only API Access**.
- Numeric search input is restricted to digits. CSS names used in SQL are escaped as SQL string literals.
- The optional Windows **Remember me** feature stores passwords encrypted with Windows DPAPI for the current Windows user. Passwords are not intentionally stored in plaintext by the application.
- TLS certificate verification is supported and **recommended for production**. Configure `ca_bundle` and enable **Verify TLS certificate**.
- HTTP 503 is treated as service-unavailable/throttling and retried with backoff rather than being interpreted as a schema error.
- Public release builds use only example cluster configuration and strip saved credentials.

## Diagnostic logs

A normal `AXLDiag` log may contain hostnames, IP addresses, proxy configuration, partition/CSS names, DNs, SQL text and AXL response data. Treat normal logs as private operational data.

Use:

```bash
python axl_diag.py --public <publisher> [cluster-id] [prefix]
```

before attaching a diagnostic log to a public GitHub issue or forum post. Public mode redacts/omits common sensitive fields, but users should still review the resulting file before posting it.

## Scope limitations

CSS-aware analysis determines whether collected route-plan patterns are located in partitions that belong to the selected CSS. It is not a full CUCM Digit Analysis simulator and should not be treated as a security control or authoritative routing proof.
