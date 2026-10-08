# Live validation status

Target CSS discovery and CSS-aware analysis have been validated successfully in live CUCM 12.5 and 14 environments. The checks below remain useful when validating additional CUCM releases or new environments.

# Live CUCM Validation Checklist for v1.1.0

Run these checks before tagging v1.1.0 as a public production release. The offline suite validates logic, but it cannot prove the CUCM SQL schema or environment-specific behavior.

## 1. Test Connection

For at least one CUCM 12.5 publisher and one CUCM 14 publisher:

- enter the dedicated read-only AXL credentials;
- select **Test Connection**;
- confirm the cluster badge shows the CUCM version;
- confirm the status reports partition and CSS counts;
- confirm the Target Partition dropdown is populated;
- confirm the Target CSS dropdown is populated.

## 2. Validate one CSS against CUCM Administration

Choose a representative CSS with several partitions.

In CUCM Administration, record the ordered partition list.

In DN Scout:

1. choose that CSS in **Target CSS**;
2. search a small extension range;
3. open **CSS Scope**;
4. confirm the CSS name, partitions and order match CUCM Administration.

Optional CLI/SQL cross-check:

```sql
select css.name as css,
       csm.sortorder,
       rp.name as partition
from callingsearchspace css
inner join callingsearchspacemember csm
  on csm.fkcallingsearchspace = css.pkid
inner join routepartition rp
  on csm.fkroutepartition = rp.pkid
where css.name = 'YOUR_CSS_NAME'
order by csm.sortorder, rp.name
```

## 3. Validate an exact DN inside the CSS

Pick a known DN in a partition that belongs to the selected CSS.

Expected result: `USED`.

The detail pane should identify the object type, DN/pattern and partition.

## 4. Validate an exact DN outside the CSS

Pick a known DN in a partition that is not a member of the selected CSS.

Expected result when Target CSS is selected: `OTHER PT` with a detail indicating that the object is outside the selected CSS.

## 5. Validate a wildcard

Choose a wildcard/translation/route pattern that covers a small candidate range.

- If its partition is in the selected CSS, covered candidates should show `CHECK`.
- If its partition is outside the selected CSS, the candidates should show `OTHER PT` rather than `CHECK`.

## 6. Validate the null partition

Use a lab-safe object in `<None>` if available.

Expected behavior: the null partition is treated as reachable even when a Target CSS is selected.

## 7. Validate HTTP 503 behavior if a safe test method exists

Do not intentionally overload a production publisher. If a lab/proxy can return HTTP 503, confirm:

- the client retries with backoff;
- the AXL schema remains unchanged;
- the final message reports service unavailable/throttling if retries are exhausted.

## 8. Validate TLS verification

With **Verify TLS certificate** enabled:

- confirm a trusted `ca_bundle` succeeds;
- confirm an untrusted/wrong CA produces a clear TLS verification error.

## 9. Validate public diagnostics

Run:

```bash
python axl_diag.py --public <publisher> <cluster-id> <prefix>
```

Open the generated `axl_diag_public_*.txt` file and confirm it does not expose:

- publisher hostname/IP;
- AXL username;
- entered prefix;
- proxy URLs;
- SQL text;
- AXL response bodies;
- local user home directory.

## 10. Screenshot review

The repository light-theme screenshot has been refreshed with synthetic v1.1.0 data. Before publication, review it and optionally capture a Windows `sv-ttk` dark-theme screenshot showing:

- Target CSS field;
- CSS Scope tab;
- generic cluster IDs/names;
- synthetic extensions only;
- no internal hostnames, IPs, names or production descriptions.

After all checks pass, update the public README and release notes, create the `v1.1.0` tag, and allow GitHub Actions to build the public Windows release and SHA-256 checksum.
