#!/usr/bin/env python3
"""
AXL connection diagnostic - run against one CUCM node and it tells you
exactly where AXL fails (network, proxy, TLS, auth, AXL version, SQL).

Usage:   python axl_diag.py [--public] <publisher-ip-or-fqdn> [cluster-id] [prefix]
         e.g. python axl_diag.py 10.10.10.5 CL2 5405
         e.g. python axl_diag.py --public 10.10.10.5 CL2 5405
         (cluster-id is from cucm_clusters.json; prefix runs a real search)
         (it will ask for the username and password)

The normal log is intended for private troubleshooting and may contain hostnames,
IP addresses, partition/CSS names, DNs, proxy settings and AXL response data.
Use --public before attaching a log to a public issue; public mode redacts/omits
those details. The password is never printed or saved in either mode.
"""
import getpass
import os
import re
import socket
import ssl
import sys
import time
import urllib.request

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("requests is missing - run:  python -m pip install requests")

LOG = []
PUBLIC_MODE = False
SENSITIVE_VALUES = set()
# Folder of the script, or of the .exe when packaged with PyInstaller
BASE_DIR = (os.path.dirname(sys.executable) if getattr(sys, "frozen", False)
            else os.path.dirname(os.path.abspath(__file__)))


def redact(text):
    text = str(text)
    if not PUBLIC_MODE:
        return text
    for value in sorted((v for v in SENSITIVE_VALUES if v), key=len, reverse=True):
        text = text.replace(value, "<redacted>")
    text = re.sub(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", "<IP>", text)
    text = re.sub(r"(?i)(https?://)([^/\s]+)", r"\1<host>", text)
    return text


def out(line=""):
    line = redact(line)
    print(line)
    LOG.append(line)


def snippet(content, n=600):
    if PUBLIC_MODE:
        size = len(content) if hasattr(content, "__len__") else "unknown"
        return f"<response body redacted in --public mode; {size} bytes>"
    text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)
    return " ".join(text.split())[:n]


def header(title):
    out()
    out("=" * 70)
    out(title)
    out("=" * 70)


def soap(method, inner, version):
    return (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        f'xmlns:ns="http://www.cisco.com/AXL/API/{version}"><soapenv:Header/><soapenv:Body>'
        f"<ns:{method}>{inner}</ns:{method}></soapenv:Body></soapenv:Envelope>")


def request(label, session, verb, url, **kw):
    out(f"\n--- {label}")
    t0 = time.time()
    try:
        r = session.request(verb, url, timeout=30, verify=False, **kw)
    except requests.exceptions.ProxyError as exc:
        out(f"RESULT : PROXY ERROR - {exc}")
        return None
    except requests.exceptions.SSLError as exc:
        out(f"RESULT : TLS ERROR - {exc}")
        return None
    except requests.exceptions.RequestException as exc:
        out(f"RESULT : CONNECTION ERROR - {exc.__class__.__name__}: {exc}")
        return None
    out(f"HTTP   : {r.status_code} {r.reason}   ({(time.time() - t0) * 1000:.0f} ms)")
    for h in ("Server", "Content-Type", "Via", "X-Cache", "Proxy-Agent", "Retry-After"):
        if h in r.headers:
            out(f"{h:7}: {r.headers[h]}")
    out(f"BODY   : {snippet(r.content)}")
    return r


def main():
    global PUBLIC_MODE
    args = sys.argv[1:]
    PUBLIC_MODE = "--public" in args
    args = [a for a in args if a != "--public"]
    host = args[0] if args else input("CUCM host/IP: ").strip()
    cluster = args[1] if len(args) > 1 else None
    prefix = args[2] if len(args) > 2 else None
    user = input("AXL username: ").strip()
    pwd = getpass.getpass("AXL password (hidden): ")
    SENSITIVE_VALUES.update((host, user, prefix or "", BASE_DIR, os.path.expanduser("~")))
    url = f"https://{host}:8443/axl/"

    header(f"AXL diagnostic for {host}   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"Python {sys.version.split()[0]}, requests {requests.__version__}")
    if PUBLIC_MODE:
        out("PUBLIC MODE: host/IP/user/prefix and response bodies are redacted for safer sharing.")
    else:
        out("PRIVATE LOG: review before sharing; it may contain CUCM/network configuration data.")

    # 1. Proxy settings - a proxy is the classic reason a browser works and Python doesn't
    header("1. Proxy settings seen by Python")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
        if os.environ.get(var):
            out(f"env {var} = {'<redacted in --public mode>' if PUBLIC_MODE else os.environ[var]}")
    proxies = urllib.request.getproxies()
    out(f"System/registry proxies : {'<redacted in --public mode>' if PUBLIC_MODE and proxies else (proxies or 'none')}")
    try:
        bypass = urllib.request.proxy_bypass(host)
    except Exception:  # noqa: BLE001
        bypass = "unknown"
    out(f"Host bypasses proxy     : {bool(bypass) if bypass != 'unknown' else bypass}")

    # 2. TCP
    header("2. TCP connect to port 8443")
    try:
        t0 = time.time()
        with socket.create_connection((host, 8443), timeout=10):
            out(f"OK - connected in {(time.time() - t0) * 1000:.0f} ms")
    except OSError as exc:
        out(f"FAILED - {exc}  (firewall/routing; nothing else will work)")

    # 3. TLS
    header("3. TLS handshake")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 8443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                out(f"OK - {tls.version()}, cipher {tls.cipher()[0]}")
    except (OSError, ssl.SSLError) as exc:
        out(f"FAILED - {exc}")

    # 4-6 run twice: with system proxy settings (what the app did) and direct
    for use_proxy in (True, False):
        s = requests.Session()
        s.trust_env = use_proxy
        s.auth = (user, pwd)
        mode = "USING system proxy settings" if use_proxy else "DIRECT (proxy ignored)"

        header(f"4. GET {url}  [{mode}]")
        request("Browser-style GET (same as your browser test)", s, "GET", url)

        header(f"5. getCCMVersion  [{mode}]")
        for ver in ("12.5", "14.0"):
            request(f"AXL {ver}", s, "POST", url, data=soap("getCCMVersion", "", ver).encode(),
                    headers={"Content-Type": "text/xml; charset=utf-8",
                             "SOAPAction": f'"CUCM:DB ver={ver} getCCMVersion"'})

        header(f"6. executeSQLQuery  [{mode}]")
        sql = "<sql>SELECT COUNT(*) AS n FROM routepartition</sql>"
        for ver in ("12.5", "14.0"):
            request(f"AXL {ver}", s, "POST", url, data=soap("executeSQLQuery", sql, ver).encode(),
                    headers={"Content-Type": "text/xml; charset=utf-8",
                             "SOAPAction": f'"CUCM:DB ver={ver} executeSQLQuery"'})

    # 7. Replay the Dial Plan Analyzer's own requests (same client code, same config)
    header("7. Dial Plan Analyzer replay (the app's exact requests)")
    try:
        sys.path.insert(0, BASE_DIR)
        import dn_scout as app
    except Exception as exc:  # noqa: BLE001
        out(f"SKIPPED - dn_scout.py not found next to this script ({exc})")
        app = None
    if app:
        try:
            cfg = app.load_config()
        except Exception as exc:  # noqa: BLE001
            out(f"Config problem: {exc}")
            cfg = None
        if cfg:
            for c in cfg["clusters"]:
                SENSITIVE_VALUES.add(c.get("host", ""))
                SENSITIVE_VALUES.add(c.get("name", ""))
                flag = "   <-- matches this host" if c["host"] == host else ""
                out(f"config {c['id']} ({c['name'] or 'no name'}): host={c['host'] or '(empty - hidden)'}"
                    f"  axl_version={c['axl_version']}{flag}")
            if not cluster:
                cluster = next((c["id"] for c in cfg["clusters"] if c["host"] == host), None)
            client = None
            if not cluster:
                out(f"!! No cluster in cucm_clusters.json has host {host}. The app is NOT "
                    "talking to this node - fix the host in the config.")
            else:
                try:
                    client = app.make_client(cfg, cluster, user, pwd, False)
                except Exception as exc:  # noqa: BLE001
                    out(f"Config problem for {cluster}: {exc}")
                    client = None
            if client:
                out(f"Replaying as cluster {cluster} -> {client.url} (AXL {client.version})")
                real_post = client.session.post

                def logged_post(url_, data=None, headers=None, **kw):
                    body = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
                    sql = body.split("<sql>")[1].split("</sql>")[0] if "<sql>" in body else ""
                    out(f"\n>>> {headers.get('SOAPAction') if headers else ''}")
                    if sql:
                        out("SQL    : <redacted in --public mode>" if PUBLIC_MODE else f"SQL    : {sql}")
                    t0 = time.time()
                    r = real_post(url_, data=data, headers=headers, **kw)
                    out(f"HTTP   : {r.status_code} {r.reason}   ({(time.time() - t0) * 1000:.0f} ms)")
                    out(f"BODY   : {snippet(r.content, 800)}")
                    return r

                client.session.post = logged_post
                app.time.sleep = lambda s: None     # don't wait on retries while diagnosing
                cancel = app.threading.Event()
                steps = [("Test Connection: version", client.version_string),
                         ("Test Connection: partitions", lambda: client.sql_paged(
                             "SELECT {page} rp.name AS ptname FROM routepartition rp "
                             "ORDER BY rp.name", 2000, cancel))]
                if prefix:
                    steps.append((f"Search {prefix}", lambda: app.search_cluster(
                        client, prefix, max(len(prefix), 6), cfg, cancel, lambda s: out(f"[{s}]"))))
                for label, fn in steps:
                    out(f"\n##### {label}")
                    try:
                        result = fn()
                        out(f"##### {label}: OK ({len(result) if hasattr(result, '__len__') else result})")
                    except Exception as exc:  # noqa: BLE001
                        out(f"##### {label}: FAILED - {exc}")

    header("How to read this")
    out("- 200 in step 6 = AXL works with that version and proxy mode.")
    out("- Works DIRECT but fails with proxy = a proxy is intercepting; the app must bypass it.")
    out("- 401 = wrong password or user not on this cluster. 403 = missing AXL role.")
    out("- 599 on one schema but 200 on another = set axl_version to the supported schema.")
    out("- 503 = service unavailable/throttling; retry/backoff and verify AXL service health.")

    safe_host = "public" if PUBLIC_MODE else host.replace(":", "_")
    path = os.path.join(BASE_DIR,
                        f"axl_diag_{safe_host}_{time.strftime('%Y%m%d_%H%M%S')}.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG))
    print(f"\nSaved to {path}")
    if getattr(sys, "frozen", False):
        input("Press Enter to close...")


if __name__ == "__main__":
    main()
