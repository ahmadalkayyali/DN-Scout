# Contributing

Thanks for helping improve DN Scout.

- **Bugs and ideas:** open an issue using the repository templates.
- **Connection problems:** generate an `AXLDiag --public` log for a public issue. Never post a raw/private diagnostic log without reviewing it.
- **Pull requests:** keep changes focused and add/update tests when matching, availability, CSS scope or AXL handling changes.
- **Read-only rule:** changes must not introduce CUCM configuration writes. Read-only AXL methods and `SELECT` statements through `executeSQLQuery` are allowed.
- **Privacy:** do not commit real publisher names/IPs, user names, DNs tied to people, credentials, customer names or proprietary dial-plan data.
- **Compatibility:** do not claim a CUCM release is supported until the relevant queries have been validated on that release.

## Development setup

Python 3.10+ is required.

```bash
python -m pip install -r requirements.txt pytest
python -m py_compile dn_scout.py axl_diag.py
python -m pytest -q tests
python dn_scout.py
```

## Adding CUCM SQL

When adding a new query:

1. keep it read-only;
2. use `SELECT` only;
3. escape any non-numeric user-supplied string using the repository's SQL literal helper or another safe equivalent;
4. handle release-specific table/column differences gracefully when practical;
5. add offline tests and document the CUCM versions actually validated.
