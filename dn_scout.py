#!/usr/bin/env python3
"""
DN Scout
=====================
Read-only AXL tool for multi-cluster dial-plan analysis across one or more
Cisco Unified CM clusters (validated on 12.5 and 14; other releases may work but are not formally validated).

Requirements : Python 3.10+ with tkinter;  pip install -r requirements.txt
Config       : cucm_clusters.json next to this script
               (copy cucm_clusters.example.json and fill in your publishers)
AXL account  : dedicated application user in a group with "Standard AXL API Users"
               and "Standard AXL Read Only API Access"
               (Cisco AXL Web Service active on each publisher)

Only SELECT statements are sent through AXL executeSQLQuery; nothing is
written to CUCM.

License: MIT - see LICENSE
"""

from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from xml.sax.saxutils import escape

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import requests
    import urllib3
except ImportError:  # handled at startup with a friendly message
    requests = None
    urllib3 = None


__version__ = "1.1.0"
APP_NAME = "DN Scout"
APP_TITLE = f"{APP_NAME} v{__version__}"
MAX_CLUSTERS = 6
STATUS_RANK = {"FREE": 0, "CHECK": 1, "OTHER PT": 2, "USED": 3}
MAX_TREE_ROWS = 20000      # rows drawn per tab; CSV export always has everything
MAX_REASONS = 6            # reasons shown per number in the Details column

DEFAULT_CONFIG = {
    "clusters": [
        {"id": "CL1", "name": "Primary", "host": "cucm1-pub.example.com", "axl_version": "12.5", "ca_bundle": ""},
        {"id": "CL2", "name": "Secondary", "host": "cucm2-pub.example.com", "axl_version": "14.0", "ca_bundle": ""},
        {"id": "CL3", "name": "Regional", "host": "", "axl_version": "12.5", "ca_bundle": ""},
    ],
    "default_username": "",
    "flag_overlaps": True,
    "page_size": 2000,
    "max_candidates": 100000,
    "timeout_seconds": 60,
    "axl_retry_attempts": 4,
    "axl_retry_base_seconds": 2,
}


def app_dir() -> str:
    if getattr(sys, "frozen", False):          # PyInstaller exe
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_PATH = os.path.join(app_dir(), "cucm_clusters.json")


class ConfigError(Exception):
    pass


class AxlError(Exception):
    pass


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def normalize_clusters(raw) -> list:
    """Accept the v1.0 list format and the legacy {"UC": {...}, "CC": {...}} format."""
    if isinstance(raw, dict):
        raw = [{"id": k, **(v if isinstance(v, dict) else {})} for k, v in raw.items()]
    out, seen = [], set()
    for i, c in enumerate(raw or []):
        if not isinstance(c, dict):
            continue
        cid = re.sub(r"[^A-Za-z0-9_-]", "", str(c.get("id") or ""))[:8] or f"CL{i + 1}"
        if cid.upper() in seen:
            raise ConfigError(f"Cluster id '{cid}' is used twice in {CONFIG_PATH}")
        seen.add(cid.upper())
        out.append({"id": cid,
                    "name": str(c.get("name") or "").strip(),
                    "host": str(c.get("host") or "").strip(),
                    "axl_version": str(c.get("axl_version") or "12.5").strip(),
                    "ca_bundle": str(c.get("ca_bundle") or "").strip()})
    if len(out) > MAX_CLUSTERS:
        raise ConfigError(f"{len(out)} clusters configured; the maximum is {MAX_CLUSTERS}.")
    return out


def is_configured(cluster: dict) -> bool:
    host = cluster.get("host", "")
    return bool(host) and not host.endswith("example.com")


def active_clusters(cfg: dict) -> list:
    return [c for c in cfg["clusters"] if is_configured(c)]


def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_CONFIG, fh, indent=2)
        raise ConfigError(
            f"A config file was created at:\n{CONFIG_PATH}\n\n"
            "Enter the publisher host for each cluster (leave host empty to hide a cluster), "
            "then try again.")
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            user_cfg = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Could not read {CONFIG_PATH}:\n{exc}") from exc
    cfg = {**DEFAULT_CONFIG, **user_cfg}
    cfg["clusters"] = normalize_clusters(user_cfg.get("clusters", DEFAULT_CONFIG["clusters"]))
    if not active_clusters(cfg):
        raise ConfigError(f"No cluster has a publisher host yet. Edit:\n{CONFIG_PATH}")
    return cfg


# --------------------------------------------------------------------------
# Saved credentials - password encrypted with Windows DPAPI (per Windows user)
# --------------------------------------------------------------------------
SECRET_PREFIX = "dpapi:"
_ENTROPY = b"DNScout-v1"  # per-application DPAPI entropy; prior pre-release credentials require re-entry
CRED_KEYS = ("saved_username", "saved_password")


def can_remember() -> bool:
    return sys.platform == "win32"


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def _to_blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _dpapi(data: bytes, encrypt: bool) -> bytes:
        blob_in, keep1 = _to_blob(data)
        entropy, keep2 = _to_blob(_ENTROPY)
        blob_out = _Blob()
        crypt32 = ctypes.windll.crypt32
        if encrypt:
            ok = crypt32.CryptProtectData(ctypes.byref(blob_in), ctypes.c_wchar_p(APP_NAME), ctypes.byref(entropy),
                                          None, None, 0x1, ctypes.byref(blob_out))
        else:
            ok = crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, ctypes.byref(entropy),
                                            None, None, 0x1, ctypes.byref(blob_out))
        if not ok:
            raise OSError(f"DPAPI error {ctypes.GetLastError()}")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


def protect_secret(text: str) -> str:
    """Encrypt for the current Windows user; the result is useless on any other account or PC."""
    if not can_remember():
        raise OSError("Saving passwords is only supported on Windows.")
    return SECRET_PREFIX + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")


def unprotect_secret(value: str) -> str:
    if not value.startswith(SECRET_PREFIX) or not can_remember():
        raise ValueError("Unsupported saved password format.")
    return _dpapi(base64.b64decode(value[len(SECRET_PREFIX):]), False).decode("utf-8")


def update_config_file(changes: dict = None, remove: tuple = ()) -> None:
    """Change top-level keys in cucm_clusters.json, keeping everything else, written atomically."""
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        raw = json.load(fh)
    raw.update(changes or {})
    for key in remove:
        raw.pop(key, None)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2)
    os.replace(tmp, CONFIG_PATH)


def cluster_label(c: dict) -> str:
    return f"{c['id']} · {c['name']}" if c.get("name") else c["id"]


def make_client(cfg: dict, cid: str, user: str, pwd: str, verify_tls: bool) -> "AxlClient":
    c = next((x for x in cfg["clusters"] if x["id"].upper() == str(cid).upper()), None)
    if c is None:
        raise ConfigError(f"Cluster '{cid}' is not defined in:\n{CONFIG_PATH}")
    if not is_configured(c):
        raise ConfigError(f"Set the publisher host for {c['id']} in:\n{CONFIG_PATH}")
    version = c["axl_version"]
    if re.fullmatch(r"\d+", version):          # "14" -> "14.0"; CUCM rejects bare majors with HTTP 599
        version += ".0"
    verify = False
    if verify_tls:
        ca = c["ca_bundle"]
        verify = (ca if os.path.isabs(ca) else os.path.join(app_dir(), ca)) if ca else True
    return AxlClient(c["id"], c["host"], user, pwd, version, verify,
                     int(cfg.get("timeout_seconds", 60)),
                     int(cfg.get("axl_retry_attempts", 4)),
                     float(cfg.get("axl_retry_base_seconds", 2)))


# --------------------------------------------------------------------------
# AXL client (raw SOAP, executeSQLQuery only - no WSDL needed)
# --------------------------------------------------------------------------
class AxlClient:
    def __init__(self, name, host, username, password, version="12.5", verify=False, timeout=60,
                 retry_attempts=4, retry_base_seconds=2):
        self.name = name
        self.host = host
        self.url = f"https://{host}:8443/axl/"
        self.version = version
        self._alt_tried = False
        self.timeout = timeout
        self.retry_attempts = max(1, int(retry_attempts))
        self.retry_base_seconds = max(0.0, float(retry_base_seconds))
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "text/xml; charset=utf-8"})
        if verify is False and urllib3 is not None:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _post(self, method: str, inner: str) -> ET.Element:
        envelope = (
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:ns="http://www.cisco.com/AXL/API/{self.version}">'
            f"<soapenv:Header/><soapenv:Body><ns:{method}>{inner}</ns:{method}>"
            "</soapenv:Body></soapenv:Envelope>")
        headers = {"SOAPAction": f'"CUCM:DB ver={self.version} {method}"'}
        last_503 = None
        for attempt in range(self.retry_attempts):
            try:
                resp = self.session.post(self.url, data=envelope.encode("utf-8"),
                                         headers=headers, timeout=self.timeout)
            except requests.exceptions.SSLError:
                raise AxlError(f"{self.name}: TLS certificate verification failed. Enable a trusted "
                               "ca_bundle for production, or disable 'Verify TLS certificate' only "
                               "when you understand the risk.")
            except requests.exceptions.RequestException as exc:
                raise AxlError(f"{self.name}: cannot reach {self.url} ({exc.__class__.__name__}).")
            if resp.status_code == 401:
                raise AxlError(f"{self.name}: authentication failed (HTTP 401). Check the "
                               "username/password and the AXL roles on this cluster.")
            if resp.status_code == 403:
                raise AxlError(f"{self.name}: access denied (HTTP 403). The user needs "
                               "'Standard AXL API Users' and 'Standard AXL Read Only API Access'.")
            if resp.status_code == 404:
                raise AxlError(f"{self.name}: AXL not found (HTTP 404). Is the Cisco AXL Web "
                               "Service activated on the publisher?")

            body = resp.content.lower()
            # HTTP 503 is service unavailable/throttling. It is not an AXL schema signal.
            # Keep the requested schema and back off before retrying.
            if resp.status_code == 503 or (
                    resp.status_code == 500 and (b"throttl" in body or b"too many" in body)):
                last_503 = resp
                if attempt + 1 < self.retry_attempts:
                    retry_after = getattr(resp, "headers", {}).get("Retry-After", "")
                    try:
                        delay = max(self.retry_base_seconds * (attempt + 1), float(retry_after))
                    except (TypeError, ValueError):
                        delay = self.retry_base_seconds * (attempt + 1)
                    time.sleep(delay)
                    continue

            # HTTP 599 is CUCM's unsupported-schema response. A version-specific 500 fault
            # can also indicate the same condition, so only these trigger the one-time fallback.
            version_problem = resp.status_code == 599 or (
                resp.status_code == 500 and b"version" in body and b"support" in body)
            if version_problem and not self._alt_tried:
                self._alt_tried = True
                old = self.version
                self.version = "14.0" if old.startswith("12") else "12.5"
                envelope = envelope.replace(f"/AXL/API/{old}", f"/AXL/API/{self.version}")
                headers = {"SOAPAction": f'"CUCM:DB ver={self.version} {method}"'}
                continue
            if resp.status_code == 599:
                snippet = re.sub(r"<[^>]+>", " ", resp.content[:400].decode("utf-8", "replace"))
                raise AxlError(
                    f"{self.name}: HTTP 599 from {self.host} after trying AXL {self.version}.\n\n"
                    "Set axl_version for this cluster in cucm_clusters.json to a schema supported "
                    "by that CUCM release.\n\n"
                    f"Server said: {' '.join(snippet.split())[:200]}")
            if resp.status_code == 503:
                continue
            if resp.status_code == 500:
                raise AxlError(f"{self.name}: {self._fault(resp.content)}")
            if resp.status_code != 200:
                raise AxlError(f"{self.name}: HTTP {resp.status_code}")
            try:
                return ET.fromstring(resp.content)
            except ET.ParseError as exc:
                raise AxlError(f"{self.name}: unreadable AXL response ({exc}).")
        if last_503 is not None:
            raise AxlError(f"{self.name}: AXL returned HTTP 503 after {self.retry_attempts} attempts. "
                           "The service may be busy/throttled or unavailable; retry after reducing "
                           "load and verify Cisco AXL Web Service health.")
        raise AxlError(f"{self.name}: AXL request failed after {self.retry_attempts} attempts.")

    @staticmethod
    def _fault(content: bytes) -> str:
        try:
            root = ET.fromstring(content)
            found = {}
            for el in root.iter():
                tag = el.tag.split("}")[-1]
                if tag in ("axlmessage", "faultstring") and el.text:
                    found[tag] = el.text.strip()
            if found:
                return found.get("axlmessage") or found["faultstring"]
        except ET.ParseError:
            pass
        return content[:300].decode("utf-8", errors="replace")

    def sql(self, query: str) -> list:
        root = self._post("executeSQLQuery", f"<sql>{escape(query)}</sql>")
        rows = []
        for el in root.iter():
            if el.tag.split("}")[-1] == "row":
                rows.append({c.tag.split("}")[-1].lower(): (c.text or "").strip() for c in el})
        return rows

    def sql_paged(self, template: str, page_size: int, cancel: threading.Event) -> list:
        """template must contain '{page}' right after SELECT and an ORDER BY clause."""
        out, skip = [], 0
        while True:
            if cancel.is_set():
                raise Cancelled()
            rows = self.sql(template.replace("{page}", f"SKIP {skip} FIRST {page_size}"))
            out.extend(rows)
            if len(rows) < page_size:
                return out
            skip += page_size

    def version_string(self) -> str:
        root = self._post("getCCMVersion", "")
        for el in root.iter():
            if el.tag.split("}")[-1] == "version" and el.text:
                return el.text.strip()
        return "unknown"


# --------------------------------------------------------------------------
# CUCM pattern engine
# --------------------------------------------------------------------------
DIGITS = frozenset("0123456789")
DIALABLE = frozenset("0123456789*#")
LITERAL_RE = re.compile(r"^(\\\+)?[0-9*#]+$")


def compile_pattern(p: str):
    """Compile a CUCM pattern into tokens [(charset, repeats)].
    repeats=True means zero-or-more. Returns None for patterns this tool
    does not evaluate (@ dial-plan patterns, malformed brackets)."""
    if "@" in p:
        return None
    tokens, i, n = [], 0, len(p)
    while i < n:
        c = p[i]
        if c == "\\" and i + 1 < n:
            tokens.append([frozenset(p[i + 1]), False])
            i += 2
        elif c == ".":
            i += 1
        elif c == "X":
            tokens.append([DIGITS, False])
            i += 1
        elif c == "!":
            tokens.append([DIGITS, False])
            tokens.append([DIGITS, True])
            i += 1
        elif c in "?+":
            if not tokens:
                return None
            if c == "?":
                tokens[-1][1] = True
            else:
                tokens.append([tokens[-1][0], True])
            i += 1
        elif c == "[":
            j = p.find("]", i)
            if j < 0:
                return None
            body = p[i + 1:j]
            negate = body.startswith("^")
            if negate:
                body = body[1:]
            chars, k = set(), 0
            while k < len(body):
                if k + 2 < len(body) and body[k + 1] == "-":
                    lo, hi = body[k], body[k + 2]
                    chars.update(chr(x) for x in range(ord(lo), ord(hi) + 1))
                    k += 3
                else:
                    chars.add(body[k])
                    k += 1
            tokens.append([DIALABLE - chars if negate else frozenset(chars), False])
            i = j + 1
        else:
            tokens.append([frozenset(c), False])
            i += 1
    return [(cs, rep) for cs, rep in tokens] or None


def literal_of_tokens(tokens):
    """If every token is a single fixed character, return that string."""
    if all(len(cs) == 1 and not rep for cs, rep in tokens):
        return "".join(next(iter(cs)) for cs, _ in tokens)
    return None


def _closure(tokens, states):
    seen, stack = set(states), list(states)
    while stack:
        s = stack.pop()
        if s < len(tokens) and tokens[s][1] and s + 1 not in seen:
            seen.add(s + 1)
            stack.append(s + 1)
    return frozenset(seen)


def _step(tokens, states, ch):
    nxt = set()
    for s in states:
        if s < len(tokens) and ch in tokens[s][0]:
            nxt.add(s if tokens[s][1] else s + 1)
    return _closure(tokens, nxt) if nxt else frozenset()


def pattern_hits(tokens, prefix: str, total: int, cancel: threading.Event) -> dict:
    """For every candidate (prefix padded to `total` digits) return
    'match'   - the pattern matches the candidate exactly, or
    'overlap' - the pattern matches a shorter/longer string sharing the
                candidate's leading digits (interdigit-timeout risk)."""
    end = len(tokens)
    states = _closure(tokens, {0})
    shorter = False
    for i, ch in enumerate(prefix):
        if i > 0 and end in states:
            shorter = True
        states = _step(tokens, states, ch)
        if not states and not shorter:
            return {}

    hits, stack, ops = {}, [(prefix, states, shorter)], 0
    while stack:
        ops += 1
        if ops % 5000 == 0 and cancel.is_set():
            raise Cancelled()
        text, st, sh = stack.pop()
        if len(text) == total:
            if end in st:
                hits[text] = "match"
            elif sh or any(s < end for s in st):
                hits[text] = "overlap"
            continue
        sh2 = sh or end in st
        if not st:
            if sh2:
                rem = total - len(text)
                for n in range(10 ** rem):
                    hits[text + str(n).zfill(rem)] = "overlap"
            continue
        for d in "0123456789":
            st2 = _step(tokens, st, d)
            if st2 or sh2:
                stack.append((text + d, st2, sh2))
    return hits


def category(enum: str, usage_name: str) -> str:
    n = (usage_name or "").strip().lower()
    if n:
        return {"device": "dn", "route": "route", "translation": "translation"}.get(n, "other")
    return {"2": "dn", "5": "route", "3": "translation"}.get(str(enum), "other")


def usage_blocks(usage_name: str) -> bool:
    """Calling/called-party transformations and templates don't consume a number."""
    n = (usage_name or "").lower()
    return not ("transformation" in n or "template" in n)


def norm_row(raw: dict, location: str) -> dict:
    usage_name = raw.get("usagename", "")
    enum = raw.get("usageenum", "")
    pt = raw.get("ptname", "")
    return {
        "location": location,
        "pkid": raw.get("pkid", ""),
        "pattern": raw.get("dnpattern", ""),
        "pt": pt,
        "pt_disp": pt or "<None>",
        "pt_norm": pt.lower(),
        "descr": raw.get("descr", ""),
        "alert": raw.get("alertname", ""),
        "usage": usage_name or f"Usage {enum}",
        "category": category(enum, usage_name),
        "blocks": usage_blocks(usage_name),
    }


def sql_literal(value: str) -> str:
    """Return a safely quoted SQL string literal for CUCM executeSQLQuery."""
    return "'" + str(value).replace("'", "''") + "'"


def _scope_text(target_css: str) -> str:
    return f" through CSS {target_css}" if target_css else ""


def fwd_match(dest: str, prefix: str, total: int) -> str:
    d = dest.replace("\\", "").strip()
    if len(d) == total and d.startswith(prefix) and d.isdigit():
        return "Exact candidate"
    return "Contains prefix"


# --------------------------------------------------------------------------
# Data collection (per cluster)
# --------------------------------------------------------------------------
NUMPLAN_COLS = ("n.pkid AS pkid, n.dnorpattern AS dnpattern, rp.name AS ptname, "
                "n.description AS descr, n.tkpatternusage AS usageenum, tpu.name AS usagename")
NUMPLAN_JOINS = ("FROM numplan n "
                 "LEFT OUTER JOIN routepartition rp ON n.fkroutepartition = rp.pkid "
                 "LEFT OUTER JOIN typepatternusage tpu ON n.tkpatternusage = tpu.enum")
BUSY_FIELDS = (("cfb", "CFB External"), ("cfbint", "CFB Internal"),
               ("cfna", "CFNA External"), ("cfnaint", "CFNA Internal"),
               ("cfur", "CFUR External"), ("cfurint", "CFUR Internal"))


def search_cluster(client: AxlClient, prefix: str, total: int, cfg: dict,
                   cancel: threading.Event, status, target_css: str = "") -> dict:
    name, page = client.name, int(cfg.get("page_size", 2000))
    res = {"name": name, "prefix_rows": [], "wild_rows": [], "devices": defaultdict(list),
           "cfa": [], "busy": [], "css_rows": [], "css_partitions": set(),
           "css_requested": target_css.strip(), "css_found": False,
           "warnings": [], "skipped_at": 0}

    def optional(label, fn):
        try:
            return fn()
        except Cancelled:
            raise
        except AxlError as exc:
            res["warnings"].append(f"{label}: {exc}")
            return []

    # 1) Route-plan rows starting with the prefix, plus shorter literal prefixes
    shorter = [prefix[:k] for k in range(1, len(prefix))]
    where = f"n.dnorpattern LIKE '{prefix}%'"
    if shorter:
        where = f"({where} OR n.dnorpattern IN ({', '.join(repr(s) for s in shorter)}))"
    status(f"{name}: reading route plan for {prefix}…")
    rows = client.sql_paged(
        f"SELECT {{page}} {NUMPLAN_COLS}, n.alertingname AS alertname {NUMPLAN_JOINS} "
        f"WHERE {where} ORDER BY n.dnorpattern, n.pkid", page, cancel)
    res["prefix_rows"] = [norm_row(r, name) for r in rows]

    # 2) Wildcard patterns that could cover numbers starting with the prefix
    status(f"{name}: reading wildcard patterns…")
    first = sorted({prefix[0], "X", "[", "!"})
    first_clause = " OR ".join(f"n.dnorpattern LIKE '{c}%'" for c in first)
    wild_clause = " OR ".join(f"n.dnorpattern LIKE '%{c}%'" for c in ("X", "!", "[", ".", "?"))
    wrows = optional("Wildcard patterns", lambda: client.sql_paged(
        f"SELECT {{page}} {NUMPLAN_COLS} {NUMPLAN_JOINS} "
        f"WHERE ({first_clause}) AND ({wild_clause}) ORDER BY n.pkid", page, cancel))
    for r in wrows:
        row = norm_row(r, name)
        if not row["blocks"]:
            continue
        tokens = compile_pattern(row["pattern"])
        if tokens is None:
            res["skipped_at"] += 1
            continue
        row["tokens"] = tokens
        res["wild_rows"].append(row)

    # 3) Devices on the DNs (for the Directory Numbers tab)
    status(f"{name}: reading devices…")
    drows = optional("Devices", lambda: client.sql_paged(
        "SELECT {page} dnm.fknumplan AS npk, d.name AS devname "
        "FROM devicenumplanmap dnm "
        "INNER JOIN device d ON dnm.fkdevice = d.pkid "
        "INNER JOIN numplan n ON dnm.fknumplan = n.pkid "
        f"WHERE n.dnorpattern LIKE '{prefix}%' ORDER BY dnm.pkid", page, cancel))
    for r in drows:
        res["devices"][r.get("npk", "")].append(r.get("devname", ""))

    # 4) Call Forward All destinations containing the prefix
    status(f"{name}: reading Call Forward All…")
    crows = optional("Call Forward All", lambda: client.sql_paged(
        "SELECT {page} n.dnorpattern AS dnpattern, rp.name AS ptname, n.description AS descr, "
        "cfd.cfadestination AS dest "
        "FROM callforwarddynamic cfd "
        "INNER JOIN numplan n ON cfd.fknumplan = n.pkid "
        "LEFT OUTER JOIN routepartition rp ON n.fkroutepartition = rp.pkid "
        f"WHERE cfd.cfadestination LIKE '%{prefix}%' ORDER BY cfd.pkid", page, cancel))
    for r in crows:
        res["cfa"].append({"location": name, "dn": r.get("dnpattern", ""),
                           "pt_disp": r.get("ptname", "") or "<None>",
                           "descr": r.get("descr", ""), "type": "CFA",
                           "dest": r.get("dest", "")})

    # 5) Busy / No Answer / Unregistered destinations containing the prefix
    status(f"{name}: reading Busy / No Answer forwarding…")
    sel = ", ".join(f"n.{f}destination AS {f}" for f, _ in BUSY_FIELDS)
    cond = " OR ".join(f"n.{f}destination LIKE '%{prefix}%'" for f, _ in BUSY_FIELDS)
    brows = optional("Busy / No Answer", lambda: client.sql_paged(
        "SELECT {page} n.dnorpattern AS dnpattern, rp.name AS ptname, n.description AS descr, "
        f"{sel} FROM numplan n "
        "LEFT OUTER JOIN routepartition rp ON n.fkroutepartition = rp.pkid "
        f"WHERE {cond} ORDER BY n.pkid", page, cancel))
    for r in brows:
        for field, label in BUSY_FIELDS:
            dest = r.get(field, "")
            if dest and prefix in dest:
                res["busy"].append({"location": name, "dn": r.get("dnpattern", ""),
                                    "pt_disp": r.get("ptname", "") or "<None>",
                                    "descr": r.get("descr", ""), "type": label, "dest": dest})

    # 6) Optional CSS scope. The null partition (<None>) is treated as globally reachable
    # during evaluation and therefore does not need to appear in callingsearchspacemember.
    css_name = target_css.strip()
    if css_name:
        status(f"{name}: reading CSS scope {css_name}…")
        try:
            css_exists = client.sql_paged(
                "SELECT {page} css.name AS cssname FROM callingsearchspace css "
                f"WHERE css.name = {sql_literal(css_name)} ORDER BY css.name", page, cancel)
            if not css_exists:
                res["warnings"].append(
                    f"Calling Search Space '{css_name}' was not found; CSS filtering was not applied "
                    "on this cluster.")
            else:
                css_rows = client.sql_paged(
                    "SELECT {page} css.name AS cssname, rp.name AS ptname, csm.sortorder AS sortorder "
                    "FROM callingsearchspace css "
                    "INNER JOIN callingsearchspacemember csm ON csm.fkcallingsearchspace = css.pkid "
                    "INNER JOIN routepartition rp ON csm.fkroutepartition = rp.pkid "
                    f"WHERE css.name = {sql_literal(css_name)} ORDER BY csm.sortorder, rp.name", page, cancel)
                res["css_found"] = True
                for r in css_rows:
                    pt = r.get("ptname", "")
                    res["css_rows"].append({"location": name, "css": r.get("cssname", css_name),
                                            "pt": pt, "pt_disp": pt or "<None>",
                                            "order": r.get("sortorder", "")})
                    res["css_partitions"].add(pt.lower())
        except Cancelled:
            raise
        except AxlError as exc:
            res["warnings"].append(
                f"Calling Search Space '{css_name}' membership could not be read ({exc}); "
                "CSS filtering was not applied on this cluster.")
            res["css_found"] = False
    return res


# --------------------------------------------------------------------------
# Availability evaluation
# --------------------------------------------------------------------------
def _desc(r):
    return f" ({r['descr']})" if r.get("descr") else ""


def evaluate_cluster(cr, prefix, total, candidates, target, flag_overlaps, cancel, target_css=""):
    """Return ({candidate: (status, [reasons])} for non-FREE, wildcard-tab rows).

    When target_css is present and its membership was successfully read on this cluster,
    route-plan conflicts outside that CSS are reported as OTHER PT rather than USED/CHECK.
    The CUCM null partition (<None>) is always considered reachable. Call-forward targets
    remain CHECK because the forwarding source may use a different CSS than the selected one.
    """
    exact, longer = defaultdict(list), defaultdict(list)
    css_active = bool(target_css and cr.get("css_found"))
    css_parts = {p.lower() for p in cr.get("css_partitions", set())}

    def in_css(row):
        return not css_active or row.get("pt_norm", "") == "" or row.get("pt_norm", "") in css_parts

    def exact_in_scope(row):
        partition_ok = target is None or row.get("pt_norm", "") == target
        return partition_ok and in_css(row)

    def add_literal(value, row):
        exact[value].append(row)
        if len(value) > total:
            longer[value[:total]].append(row)

    for r in cr["prefix_rows"]:
        if r["blocks"] and LITERAL_RE.match(r["pattern"]):
            add_literal(r["pattern"].replace("\\", ""), r)

    wild_hits, wild_tab = defaultdict(list), []
    for w in cr["wild_rows"]:
        lit = literal_of_tokens(w["tokens"])
        if lit is not None:
            add_literal(lit, w)
            continue
        hits = pattern_hits(w["tokens"], prefix, total, cancel)
        if not hits:
            continue
        matched = sum(1 for k in hits.values() if k == "match")
        overlapped = len(hits) - matched
        example = min((c for c, k in hits.items() if k == "match"), default=min(hits))
        wild_tab.append({**w, "matched": matched, "overlapped": overlapped, "example": example,
                         "css_reachable": in_css(w)})
        for cand, kind in hits.items():
            wild_hits[cand].append((w, kind))

    fwd = defaultdict(list)
    for f in cr["cfa"] + cr["busy"]:
        fwd[f["dest"].replace("\\", "").strip()].append(f)

    out = {}
    for idx, cand in enumerate(candidates):
        if idx % 5000 == 0 and cancel.is_set():
            raise Cancelled()
        reasons, used, other, check = [], False, False, False
        for r in exact.get(cand, ()):
            if exact_in_scope(r):
                used = True
                scope = _scope_text(target_css) if css_active else ""
                reasons.append(f"{r['usage']} {r['pattern']} in {r['pt_disp']}{scope}{_desc(r)}")
            else:
                other = True
                why = []
                if target is not None and r["pt_norm"] != target:
                    why.append("outside target PT")
                if css_active and not in_css(r):
                    why.append(f"outside CSS {target_css}")
                reasons.append(f"{r['usage']} {r['pattern']} in {r['pt_disp']} ({', '.join(why) or 'outside scope'}){_desc(r)}")

        if flag_overlaps:
            for k in range(1, total):
                for r in exact.get(cand[:k], ()):
                    if in_css(r):
                        check = True
                        reasons.append(f"Overlap: shorter {r['usage']} {r['pattern']} in {r['pt_disp']}")
                    elif css_active:
                        other = True
                        reasons.append(f"Outside CSS {target_css}: shorter overlap {r['usage']} {r['pattern']} in {r['pt_disp']}")
            for r in longer.get(cand, ()):
                if in_css(r):
                    check = True
                    reasons.append(f"Overlap: longer {r['usage']} {r['pattern']} in {r['pt_disp']}")
                elif css_active:
                    other = True
                    reasons.append(f"Outside CSS {target_css}: longer overlap {r['usage']} {r['pattern']} in {r['pt_disp']}")

        for w, kind in wild_hits.get(cand, ()):
            if not in_css(w):
                if css_active:
                    other = True
                    reasons.append(f"Outside CSS {target_css}: {w['usage']} {w['pattern']} in {w['pt_disp']}")
                continue
            if kind == "match":
                check = True
                reasons.append(f"Covered by {w['usage']} {w['pattern']} in {w['pt_disp']}")
            elif flag_overlaps:
                check = True
                reasons.append(f"Overlap: {w['usage']} {w['pattern']} in {w['pt_disp']}")

        for f in fwd.get(cand, ()):
            check = True
            reasons.append(f"{f['type']} target of {f['dn']} in {f['pt_disp']}")

        if used:
            out[cand] = ("USED", reasons)
        elif other:
            out[cand] = ("OTHER PT", reasons)
        elif check:
            out[cand] = ("CHECK", reasons)
    return out, wild_tab


def build_report(cluster_results, prefix, total, target_text, flag_overlaps, cancel, target_css_text=""):
    rem = total - len(prefix)
    candidates = [prefix + str(i).zfill(rem) for i in range(10 ** rem)] if rem else [prefix]
    t = target_text.strip()
    target = None if not t else ("" if t.lower() in ("<none>", "none") else t.lower())
    target_css = target_css_text.strip()

    per_cluster, report = {}, {k: [] for k in
                               ("dn", "route", "translation", "other", "wildcard", "fwd", "busy", "css")}
    warnings, skipped = [], 0
    for cr in cluster_results:
        statuses, wild_tab = evaluate_cluster(cr, prefix, total, candidates, target,
                                              flag_overlaps, cancel, target_css)
        per_cluster[cr["name"]] = statuses
        report["wildcard"].extend(wild_tab)
        report["fwd"].extend(cr["cfa"])
        report["busy"].extend(cr["busy"])
        report["css"].extend(cr.get("css_rows", []))
        warnings.extend(f"{cr['name']} - {w}" for w in cr["warnings"])
        skipped += cr["skipped_at"]
        for r in cr["prefix_rows"]:
            if r["category"] == "dn":
                r = {**r, "devices": ", ".join(sorted(cr["devices"].get(r["pkid"], [])))}
            report[r["category"]].append(r)

    ids = [cr["name"] for cr in cluster_results]
    multi = len(ids) > 1
    counts = {s: 0 for s in STATUS_RANK}
    avail = []
    for cand in candidates:
        overall, details, per = "FREE", [], {}
        for cid in ids:
            st, reasons = per_cluster[cid].get(cand, ("FREE", []))
            per[cid] = st
            if STATUS_RANK[st] > STATUS_RANK[overall]:
                overall = st
            details.extend(f"{cid}: {r}" if multi else r for r in reasons)
        full = list(details)
        if len(details) > MAX_REASONS:
            details = details[:MAX_REASONS] + [f"+{len(details) - MAX_REASONS} more"]
        counts[overall] += 1
        avail.append({"number": cand, "status": overall, "per": per,
                      "details": " | ".join(details), "full": full})

    report.update(avail=avail, counts=counts, warnings=warnings, skipped_at=skipped,
                  n_prefix=sum(len(cr["prefix_rows"]) for cr in cluster_results),
                  prefix=prefix, total=total, cluster_ids=ids, target_css=target_css,
                  target_partition=target_text.strip())
    return report


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------
def natural_key(s: str):
    return [(0, int(t), "") if t.isdigit() else (1, 0, t.lower())
            for t in re.split(r"(\d+)", s) if t]


TABS = {
    # cluster status columns are inserted after "Status" at runtime, one per selected cluster
    "avail": ("Availability", [("Number", 110), ("Status", 90), ("Details", 700)]),
    "dn": ("DNs", [("Cluster", 70), ("Pattern", 120), ("Partition", 160),
                                 ("Description", 220), ("Alerting Name", 160), ("Devices", 260)]),
    "route": ("Route Patterns", [("Cluster", 70), ("Pattern", 160), ("Partition", 180),
                                 ("Description", 400)]),
    "translation": ("Translations", [("Cluster", 70), ("Pattern", 160),
                                             ("Partition", 180), ("Description", 400)]),
    "other": ("Other", [("Cluster", 70), ("Pattern", 160), ("Partition", 180),
                                   ("Usage", 160), ("Description", 300)]),
    "wildcard": ("Wildcards", [("Cluster", 70), ("Pattern", 160), ("Partition", 170),
                                       ("Usage", 130), ("Description", 220), ("Matches", 70),
                                       ("Overlaps", 70), ("Example", 100)]),
    "fwd": ("Forward All", [("Cluster", 70), ("DN", 120), ("Partition", 160),
                                  ("Description", 220), ("CFA Destination", 160),
                                  ("Match", 120)]),
    "busy": ("Busy / No Answer", [("Cluster", 70), ("DN", 120), ("Partition", 160),
                                         ("Description", 200), ("Type", 110),
                                         ("Destination", 150), ("Match", 120)]),
    "css": ("CSS Scope", [("Cluster", 70), ("Calling Search Space", 220),
                             ("Partition", 220), ("Order", 70)]),
}


try:
    import sv_ttk            # Windows 11 "Sun Valley" theme:  pip install sv-ttk
except ImportError:
    sv_ttk = None

ACCENT = "#2563eb"
STATUS_ORDER = ("FREE", "CHECK", "OTHER PT", "USED")
STATUS_COLORS = {"FREE": "#1e7e34", "CHECK": "#8a5a00", "OTHER PT": "#b4530a", "USED": "#c5221f"}  # 4.5:1+ with white text
PALETTES = {
    "light": {"text": "#1f2328", "muted": "#6b7280", "chip": "#eef1f4", "border": "#d0d7de",
              "detail": "#ffffff",
              "rows": {"USED": "#fde7e9", "OTHER PT": "#feeedd", "CHECK": "#fff6d6", "FREE": "#e6f5ea"}},
    "dark": {"text": "#f3f3f3", "muted": "#a0a4ab", "chip": "#2f3237", "border": "#474b52",
             "detail": "#2a2a2a",
             "rows": {"USED": "#4a2326", "OTHER PT": "#4a3320", "CHECK": "#433c1c", "FREE": "#1f3d29"}},
}


class ClusterPicker(tk.Frame):
    """Multi-select toggle bar: All | CL1 | CL2 | CL3 ... built from the config."""

    def __init__(self, master, font):
        super().__init__(master, bd=0, highlightthickness=1)
        self.font, self.ids, self.selected, self.labels, self.pal = font, [], set(), {}, None

    def set_clusters(self, ids):
        keep = self.selected & set(ids)
        for lb in self.labels.values():
            lb.destroy()
        self.ids, self.labels = list(ids), {}
        self.selected = keep or set(ids)
        for i, opt in enumerate(["All"] + self.ids):
            lb = tk.Label(self, text=opt, padx=14, pady=5, cursor="hand2", font=self.font)
            lb.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 1, 0))
            lb.bind("<Button-1>", lambda e, o=opt: self.toggle(o))
            self.labels[opt] = lb
        if self.pal:
            self.refresh()

    def toggle(self, opt):
        if not self.ids:
            return
        if opt == "All":
            self.selected = set(self.ids) if self.selected != set(self.ids) else {self.ids[0]}
        elif opt in self.selected and len(self.selected) > 1:
            self.selected.discard(opt)
        else:
            self.selected.add(opt)
        self.refresh()

    def chosen(self):
        return [i for i in self.ids if i in self.selected]

    def refresh(self, pal=None):
        self.pal = pal or self.pal
        p = self.pal
        self.configure(bg=p["border"], highlightbackground=p["border"])
        for opt, lb in self.labels.items():
            on = self.selected == set(self.ids) if opt == "All" else opt in self.selected
            lb.configure(bg=ACCENT if on else p["chip"], fg="#ffffff" if on else p["text"])


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x820")
        self.minsize(1000, 640)
        self.msgq: queue.Queue = queue.Queue()
        self.cancel_evt: threading.Event | None = None
        self.running = False
        self.report: dict | None = None
        self.trees: dict = {}
        self.tab_data: dict = {k: [] for k in TABS}     # key -> [(values, tag, payload)]
        self.active_status = {"FREE", "CHECK"}
        self.theme = "light"
        ff = "Segoe UI" if sys.platform == "win32" else "TkDefaultFont"
        self.f_title = (ff, 18, "bold")
        self.f_sub = (ff, 10)
        self.f_small = (ff, 9)
        self.f_chip = (ff, 10, "bold")
        self.f_mono = ("Consolas", 10) if sys.platform == "win32" else ("TkFixedFont", 10)
        self._apply_theme(first=True)
        self._build()
        self._apply_palette()
        self._initial_config()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind_all("<Control-f>", lambda e: self.filter_entry.focus_set())
        self.after(100, self._poll)

    # ---- theme ----------------------------------------------------------
    def _apply_theme(self, first=False):
        st = ttk.Style(self)
        if sv_ttk is not None:
            sv_ttk.set_theme(self.theme)
        elif first:
            st.theme_use("clam")
            st.configure("Accent.TButton", background=ACCENT, foreground="#ffffff")
            st.map("Accent.TButton", background=[("active", "#1d4ed8"), ("disabled", "#9db4ea")])
        st.configure("Title.TLabel", font=self.f_title)
        st.configure("Muted.TLabel", font=self.f_small)
        st.configure("Section.TLabel", font=(self.f_title[0], 11, "bold"))

        def fixed(option):  # Tk 8.6.9 Treeview tag-colour bug workaround
            return [e for e in st.map("Treeview", query_opt=option) if e[:2] != ("!disabled", "!selected")]
        st.map("Treeview", foreground=fixed("foreground"), background=fixed("background"))

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        self._apply_theme()
        self._apply_palette()

    def _apply_palette(self):
        pal = PALETTES[self.theme]
        bg = ttk.Style(self).lookup("TFrame", "background") or "#fafafa"
        ttk.Style(self).configure("Muted.TLabel", foreground=pal["muted"])
        self.picker.refresh(pal)
        for frame in (self.chip_bar, self.pill_bar):
            frame.configure(bg=bg)
        self._paint_pills(bg)
        self._paint_chips(bg)
        self.detail.configure(bg=pal["detail"], fg=pal["text"], insertbackground=pal["text"],
                              highlightbackground=pal["border"], highlightcolor=pal["border"])
        for s, color in pal["rows"].items():
            self.trees["avail"].tag_configure(s, background=color)
        self.theme_btn.configure(text="☀  Light" if self.theme == "dark" else "☾  Dark")
        if sv_ttk is None:
            self.theme_btn.grid_remove()

    # ---- layout ---------------------------------------------------------
    def _build(self):
        root = ttk.Frame(self, padding=(18, 14, 18, 8))
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(4, weight=1)

        # Header: title left, cluster status pills + theme toggle right
        head = ttk.Frame(root)
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        tbox = ttk.Frame(head)
        tbox.grid(row=0, column=0, sticky="w")
        ttk.Label(tbox, text=APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(tbox, text=f"v{__version__}", style="Muted.TLabel").pack(side="left", padx=(10, 0), pady=(8, 0))
        ttk.Label(head, text="Read-only AXL analysis for dial-plan availability, conflicts, CSS scope and call-forward destinations",
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w")
        self.pill_bar = tk.Frame(head)
        self.pill_bar.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))   # own row: never squeezes the title
        self.pills, self.pill_state, self.cluster_names = {}, {}, {}
        self.theme_btn = ttk.Button(head, command=self.toggle_theme, width=9)
        self.theme_btn.grid(row=0, column=2, rowspan=2, sticky="e")

        # Connection card
        conn = ttk.LabelFrame(root, text="  Connection  ", padding=(14, 8, 14, 12))
        conn.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        for col, text in enumerate(("Clusters", "Username", "Password")):
            ttk.Label(conn, text=text, style="Muted.TLabel").grid(row=0, column=col, sticky="w", pady=(0, 3))
        self.picker = ClusterPicker(conn, self.f_sub)
        self.picker.grid(row=1, column=0, sticky="w", padx=(0, 18))
        self.user_var, self.pwd_var = tk.StringVar(), tk.StringVar()
        ttk.Entry(conn, textvariable=self.user_var).grid(row=1, column=1, sticky="ew", padx=(0, 12))
        ttk.Entry(conn, textvariable=self.pwd_var, show="•").grid(row=1, column=2, sticky="ew", padx=(0, 18))
        self.verify_var = tk.BooleanVar(value=False)
        sw_style = "Switch.TCheckbutton" if sv_ttk is not None else "TCheckbutton"
        self.remember_var = tk.BooleanVar(value=False)
        self.remember_chk = ttk.Checkbutton(conn, text="Remember me", variable=self.remember_var,
                                            style=sw_style, command=self._on_remember_toggle)
        self.remember_chk.grid(row=1, column=3, padx=(0, 14))
        if not can_remember():
            self.remember_chk.state(["disabled"])
        ttk.Checkbutton(conn, text="Verify TLS certificate (recommended)", variable=self.verify_var, style=sw_style).grid(
            row=1, column=4, padx=(0, 14))
        self.test_btn = ttk.Button(conn, text="Test Connection", command=self.on_test)
        self.test_btn.grid(row=1, column=5, sticky="e")
        conn.columnconfigure(1, weight=1)
        conn.columnconfigure(2, weight=1)

        # Search card
        srch = ttk.LabelFrame(root, text="  Analyze candidate numbers  ", padding=(14, 8, 14, 10))
        srch.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        for col, text in enumerate(("Starts with", "Digits", "Target partition (optional)", "Target CSS (optional)")):
            ttk.Label(srch, text=text, style="Muted.TLabel").grid(row=0, column=col, sticky="w", pady=(0, 3))
        self.prefix_var = tk.StringVar()
        pe = ttk.Entry(srch, textvariable=self.prefix_var, width=16)
        pe.grid(row=1, column=0, sticky="w", padx=(0, 12))
        pe.bind("<Return>", lambda e: self.on_search())
        self.digits_var = tk.StringVar(value="6")
        ttk.Spinbox(srch, from_=1, to=15, textvariable=self.digits_var, width=5).grid(
            row=1, column=1, sticky="w", padx=(0, 12))
        self.pt_var = tk.StringVar()
        self.pt_combo = ttk.Combobox(srch, textvariable=self.pt_var)
        self.pt_combo.grid(row=1, column=2, sticky="ew", padx=(0, 12))
        self.css_var = tk.StringVar()
        self.css_combo = ttk.Combobox(srch, textvariable=self.css_var)
        self.css_combo.grid(row=1, column=3, sticky="ew", padx=(0, 18))
        self.search_btn = ttk.Button(srch, text="Search", style="Accent.TButton", width=16,
                                     command=self._search_or_cancel)
        self.search_btn.grid(row=1, column=4, sticky="e")
        ttk.Label(srch, style="Muted.TLabel", text=(
            "Partition limits exact-use scope. Target CSS limits route-plan/wildcard conflicts to partitions "
            "reachable through that CSS; <None> remains globally reachable. Call-forward targets stay CHECK.")
        ).grid(row=2, column=0, columnspan=5, sticky="w", pady=(8, 0))
        srch.columnconfigure(2, weight=1)
        srch.columnconfigure(3, weight=1)

        # Results toolbar: status chips (Availability) or row count, filter, export
        bar = ttk.Frame(root)
        bar.grid(row=3, column=0, sticky="ew", pady=(14, 6))
        bar.columnconfigure(1, weight=1)
        self.chip_bar = tk.Frame(bar)
        self.chip_bar.grid(row=0, column=0, sticky="w")
        self.chips = {}
        for key in ("All",) + STATUS_ORDER:
            lb = tk.Label(self.chip_bar, font=self.f_chip, padx=12, pady=4, cursor="hand2")
            lb.pack(side="left", padx=(0, 6))
            lb.bind("<Button-1>", lambda e, k=key: self._chip_click(k))
            self.chips[key] = lb
        self.count_lbl = ttk.Label(bar, style="Muted.TLabel")
        ttk.Label(bar, text="Filter", style="Muted.TLabel").grid(row=0, column=2, padx=(0, 6))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._render(self._current_key()))
        self.filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=26)
        self.filter_entry.grid(row=0, column=3, padx=(0, 10))
        self.export_btn = ttk.Button(bar, text="Export CSV", command=self.on_export, state="disabled")
        self.export_btn.grid(row=0, column=4)

        # Tabs
        body = ttk.Frame(root)
        body.grid(row=4, column=0, sticky="nsew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.nb = ttk.Notebook(body)
        self.nb.grid(row=0, column=0, sticky="nsew")
        self.tab_keys = []
        for key, (title, cols) in TABS.items():
            self.trees[key] = self._make_tree(key, title, cols)
            self.tab_keys.append(key)
        self.nb.bind("<<NotebookTabChanged>>", lambda e: self._on_tab())

        # Detail pane
        self.detail = tk.Text(body, height=4, wrap="word", bd=0, highlightthickness=1,
                              font=self.f_mono, padx=10, pady=6)
        self.detail.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self._set_detail("Select a row to see full details. Ctrl+C copies selected rows, Ctrl+F jumps to Filter.")

        # Status bar
        sb = ttk.Frame(root)
        sb.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        self.status_var = tk.StringVar(value="Ready. Test the connection, then search.")
        ttk.Label(sb, textvariable=self.status_var, style="Muted.TLabel").pack(side="left", fill="x", expand=True)
        self.progress = ttk.Progressbar(sb, mode="indeterminate", length=180)   # shown only while busy

    def _make_tree(self, key, title, cols):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text=title)
        ids = [f"c{i}" for i in range(len(cols))]
        tree = ttk.Treeview(frame, columns=ids, show="headings", selectmode="extended")
        for cid, (text, width) in zip(ids, cols):
            tree.heading(cid, text=text, anchor="w", command=lambda c=cid, t=tree: self._sort(t, c, False))
            tree.column(cid, width=width, anchor="w", stretch=True)
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.bind("<Control-c>", lambda e, t=tree: self._copy(t))
        tree.bind("<Control-a>", lambda e, t=tree: t.selection_set(t.get_children()))
        tree.bind("<<TreeviewSelect>>", lambda e, k=key: self._on_select(k))
        return tree

    # ---- pills / chips ------------------------------------------------
    def _paint_pills(self, bg=None):
        pal = PALETTES[self.theme]
        for name, lb in self.pills.items():
            state, info = self.pill_state[name]
            ok_c, bad_c = ("#6fd28a", "#f28b82") if self.theme == "dark" else ("#1e7e34", "#c5221f")
            dot = {"ok": ok_c, "fail": bad_c}.get(state, pal["muted"])
            compact = len(self.pills) > 3          # keep the header readable with 4-6 clusters
            label = f"{name} · {self.cluster_names[name]}" if self.cluster_names.get(name) and not compact else name
            lb.configure(text=f"●  {label}   {info}", fg=dot if state != "idle" else pal["muted"],
                         bg=pal["chip"])

    def _paint_chips(self, bg=None):
        pal = PALETTES[self.theme]
        counts = self.report["counts"] if self.report else {s: 0 for s in STATUS_ORDER}
        total = sum(counts.values())
        all_on = self.active_status == set(STATUS_ORDER)
        for key, lb in self.chips.items():
            if key == "All":
                on, color, text = all_on, ACCENT, f"All  {total}"
            else:
                on, color, text = key in self.active_status, STATUS_COLORS[key], f"{key}  {counts[key]}"
            lb.configure(text=text, bg=color if on else pal["chip"],
                         fg="#ffffff" if on else (color if key != "All" else pal["text"]))

    def _chip_click(self, key):
        if key == "All":
            self.active_status = set(STATUS_ORDER) if self.active_status != set(STATUS_ORDER) else {"FREE"}
        elif key in self.active_status and len(self.active_status) > 1:
            self.active_status.discard(key)
        else:
            self.active_status.add(key)
        self._paint_chips()
        self._render("avail")

    # ---- table helpers -------------------------------------------------
    def _current_key(self):
        try:
            return self.tab_keys[self.nb.index(self.nb.select())]
        except (tk.TclError, IndexError):
            return "avail"

    def _on_tab(self):
        key = self._current_key()
        if key == "avail":
            self.count_lbl.grid_remove()
            self.chip_bar.grid()
        else:
            self.chip_bar.grid_remove()
            self.count_lbl.grid(row=0, column=0, sticky="w")
        self._render(key)

    def _visible(self, key):
        rows = self.tab_data[key]
        if key == "avail":
            rows = [r for r in rows if r[1] in self.active_status]
        needle = self.filter_var.get().strip().lower()
        if needle:
            rows = [r for r in rows if needle in " ".join(str(v) for v in r[0]).lower()]
        return rows

    def _render(self, key):
        tree = self.trees[key]
        tree.delete(*tree.get_children())
        rows = self._visible(key)
        for i, (values, tag, _payload) in enumerate(rows[:MAX_TREE_ROWS]):
            tree.insert("", "end", iid=str(i), values=values, tags=(tag,) if tag else ())
        shown = min(len(rows), MAX_TREE_ROWS)
        extra = f" (showing first {MAX_TREE_ROWS:,})" if len(rows) > MAX_TREE_ROWS else ""
        self.count_lbl.configure(text=f"{len(rows):,} of {len(self.tab_data[key]):,} rows{extra}")
        self._rows_on_screen = (key, rows[:shown])

    def _on_select(self, key):
        tree = self.trees[key]
        sel = tree.selection()
        if not sel or getattr(self, "_rows_on_screen", (None,))[0] != key:
            return
        values, _tag, payload = self._rows_on_screen[1][int(sel[0])]
        if key == "avail":
            per = ", ".join(f"{k} {v}" for k, v in payload["per"].items())
            lines = [f"{payload['number']}   {payload['status']}   ({per})"]
            lines += [f"  • {r}" for r in payload["full"]] or ["  No route-plan, wildcard or forwarding hits."]
        else:
            heads = [tree.heading(c, "text") for c in tree["columns"]]
            lines = [f"{h}: {v}" for h, v in zip(heads, values) if str(v)]
        self._set_detail("\n".join(lines))

    def _set_detail(self, text):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _sort(self, tree, col, reverse):
        items = [(tree.set(k, col), k) for k in tree.get_children("")]
        items.sort(key=lambda x: natural_key(x[0]), reverse=reverse)
        for i, (_, k) in enumerate(items):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort(tree, col, not reverse))

    def _copy(self, tree):
        sel = tree.selection()
        if not sel:
            return
        heads = [tree.heading(c, "text") for c in tree["columns"]]
        lines = ["\t".join(heads)] + ["\t".join(str(v) for v in tree.item(i, "values")) for i in sel]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status_var.set(f"Copied {len(sel)} row(s) to clipboard.")

    def _setup_clusters(self, cfg):
        """(Re)build cluster badges, picker buttons and availability columns from the config."""
        active = active_clusters(cfg)
        ids = [c["id"] for c in active]
        if ids == list(self.pills) and all(self.cluster_names.get(c["id"]) == c["name"] for c in active):
            return
        for lb in self.pills.values():
            lb.destroy()
        self.pills = {}
        self.cluster_names = {c["id"]: c["name"] for c in active}
        for c in active:
            lb = tk.Label(self.pill_bar, font=self.f_small, padx=10, pady=4)
            lb.pack(side="left", padx=(0, 6))
            self.pills[c["id"]] = lb
            self.pill_state.setdefault(c["id"], ("idle", "not tested"))
        self.picker.set_clusters(ids)
        self._paint_pills()
        if not self.report:
            self._set_avail_columns(ids)

    def _reload_clusters(self):
        """Re-read the config on the UI thread so edits to cucm_clusters.json apply without a restart."""
        try:
            cfg = load_config()
        except ConfigError as exc:
            messagebox.showerror(APP_TITLE, str(exc))
            return None
        self._setup_clusters(cfg)
        return cfg

    def _set_avail_columns(self, ids):
        cols = [("Number", 110), ("Status", 90)] + [(i, 80) for i in ids] + [("Details", 700)]
        tree = self.trees["avail"]
        cids = [f"c{i}" for i in range(len(cols))]
        tree.configure(columns=cids, displaycolumns=cids)
        for cid, (text, width) in zip(cids, cols):
            tree.heading(cid, text=text, anchor="w", command=lambda c=cid, t=tree: self._sort(t, c, False))
            tree.column(cid, width=width, anchor="w", stretch=True)

    def _initial_config(self):
        try:
            cfg = load_config()
            self.user_var.set(cfg.get("saved_username") or cfg.get("default_username", ""))
            self._setup_clusters(cfg)
            saved = cfg.get("saved_password")
            if saved and can_remember():
                try:
                    self.pwd_var.set(unprotect_secret(saved))
                    self.remember_var.set(True)
                    self.status_var.set("Signed in with saved credentials. Click Test Connection.")
                except Exception:  # noqa: BLE001 - other Windows user / PC, or a copied config
                    self.status_var.set("A saved password exists but belongs to another Windows account "
                                        "or PC - enter your password.")
        except ConfigError as exc:
            msg = str(exc)
            self.status_var.set("Edit cucm_clusters.json with your publisher hostnames.")
            self.after(300, lambda: messagebox.showinfo(APP_TITLE, msg))

    # ---- worker plumbing ----------------------------------------------
    def _status(self, text):
        self.msgq.put(("status", text, None))

    def _start(self, work, on_done):
        self.cancel_evt = threading.Event()
        cancel = self.cancel_evt

        def runner():
            try:
                self.msgq.put(("done", on_done, work(cancel)))
            except Cancelled:
                self.msgq.put(("cancelled", None, None))
            except (AxlError, ConfigError, ValueError) as exc:
                self.msgq.put(("error", str(exc), None))
            except Exception as exc:  # noqa: BLE001
                self.msgq.put(("error", f"Unexpected error: {exc!r}", None))

        self._busy(True)
        threading.Thread(target=runner, daemon=True).start()

    def _busy(self, on):
        self.running = on
        self.test_btn.config(state="disabled" if on else "normal")
        # One primary button that becomes Cancel while a search runs
        self.search_btn.config(text="Cancel" if on else "Search",
                               style="TButton" if on else "Accent.TButton")
        if on:
            self.export_btn.config(state="disabled")
            self.progress.configure(mode="indeterminate", value=0)
            self.progress.pack(side="right")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)   # clear leftover fill
            self.progress.pack_forget()
            self.export_btn.config(state="normal" if self.report else "disabled")

    def _poll(self):
        try:
            while True:
                kind, a, b = self.msgq.get_nowait()
                if kind == "status":
                    self.status_var.set(a)
                elif kind == "done":
                    self._busy(False)
                    a(b)
                elif kind == "cancelled":
                    self._busy(False)
                    self.status_var.set("Cancelled.")
                elif kind == "error":
                    self._busy(False)
                    self.status_var.set("Error - see message.")
                    messagebox.showerror(APP_TITLE, a)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _clusters(self):
        return self.picker.chosen()

    def _on_remember_toggle(self):
        if self.remember_var.get():
            self.status_var.set("Your username and encrypted password will be saved after the next "
                                "successful Test Connection.")
            return
        try:
            update_config_file(remove=CRED_KEYS)
            self.status_var.set("Saved credentials removed from cucm_clusters.json.")
        except (OSError, ValueError) as exc:
            messagebox.showwarning(APP_TITLE, f"Could not update the config file:\n{exc}")

    def _save_creds(self, user, pwd):
        if not (self.remember_var.get() and can_remember()):
            return ""
        try:
            update_config_file({"saved_username": user, "saved_password": protect_secret(pwd)})
            return "  ·  credentials saved (encrypted)"
        except (OSError, ValueError) as exc:
            messagebox.showwarning(APP_TITLE, f"Could not save credentials:\n{exc}")
            return ""

    def _creds(self):
        user, pwd = self.user_var.get().strip(), self.pwd_var.get()
        if not user or not pwd:
            messagebox.showwarning(APP_TITLE, "Enter the AXL username and password.")
            return None
        return user, pwd

    # ---- actions -------------------------------------------------------
    def on_test(self):
        creds = self._creds()
        if not creds or self._reload_clusters() is None:
            return
        clusters, verify = self._clusters(), self.verify_var.get()
        self._tested_creds = creds

        def work(cancel):
            cfg = load_config()
            results, parts, css_names = [], set(), set()
            for name in clusters:
                self._status(f"{name}: connecting…")
                try:
                    client = make_client(cfg, name, *creds, verify)
                    try:
                        ver = client.version_string()
                    except AxlError:
                        ver = "version n/a"
                    rows = client.sql_paged("SELECT {page} rp.name AS ptname FROM routepartition rp "
                                            "ORDER BY rp.name", 2000, cancel)
                    parts.update(r["ptname"] for r in rows if r.get("ptname"))
                    try:
                        css_rows = client.sql_paged(
                            "SELECT {page} css.name AS cssname FROM callingsearchspace css ORDER BY css.name",
                            2000, cancel)
                        css_names.update(r["cssname"] for r in css_rows if r.get("cssname"))
                        css_info = f"{len(css_rows)} CSSs"
                    except AxlError:
                        css_rows = []
                        css_info = "CSS list unavailable"
                    results.append((name, True, f"{ver}  ·  {len(rows)} PTs · {css_info}", client.host))
                except (AxlError, ConfigError) as exc:
                    results.append((name, False, str(exc), ""))
            return results, sorted(parts, key=str.lower), sorted(css_names, key=str.lower)

        self._start(work, self._test_done)

    def _test_done(self, result):
        results, parts, css_names = result
        self.pt_combo["values"] = ["<None>"] + parts
        self.css_combo["values"] = css_names
        failures = []
        for name, ok, info, host in results:
            self.pill_state[name] = ("ok", info.split("  ·")[0]) if ok else ("fail", "failed")
            if not ok:
                failures.append(info)
        self._paint_pills()
        saved = self._save_creds(*self._tested_creds) if any(ok for _, ok, _, _ in results) else ""
        self.status_var.set(" | ".join(f"{n}: {'OK - ' + i if ok else 'FAILED'}" for n, ok, i, _ in results)
                            + saved)
        if failures:
            messagebox.showerror(APP_TITLE, "\n\n".join(failures))

    def _search_or_cancel(self):
        if self.running:
            self.on_cancel()
        else:
            self.on_search()

    def on_search(self):
        if self.running:
            return
        creds = self._creds()
        if not creds or self._reload_clusters() is None:
            return
        prefix = self.prefix_var.get().strip()
        if not re.fullmatch(r"\d+", prefix):
            messagebox.showwarning(APP_TITLE, "'Starts with' must be digits only.")
            return
        try:
            total = int(self.digits_var.get())
        except ValueError:
            total = 0
        if total < len(prefix) or total > 15:
            messagebox.showwarning(APP_TITLE, f"Digits must be between {len(prefix)} and 15.")
            return
        clusters, verify = self._clusters(), self.verify_var.get()
        target, target_css = self.pt_var.get(), self.css_var.get().strip()

        def work(cancel):
            cfg = load_config()
            limit = int(cfg.get("max_candidates", 100000))
            if 10 ** (total - len(prefix)) > limit:
                raise ValueError(f"{prefix} padded to {total} digits is "
                                 f"{10 ** (total - len(prefix)):,} numbers (limit {limit:,}). "
                                 "Use a longer prefix or raise max_candidates in the config.")
            results = []
            for n, cid in enumerate(clusters, 1):
                self._status(f"{cid}: connecting…  (cluster {n} of {len(clusters)})")
                client = make_client(cfg, cid, *creds, verify)
                results.append(search_cluster(client, prefix, total, cfg, cancel, self._status, target_css))
            self._status("Evaluating candidates…")
            return build_report(results, prefix, total, target, bool(cfg.get("flag_overlaps", True)), cancel, target_css)

        self._start(work, self._search_done)

    def on_cancel(self):
        if self.cancel_evt:
            self.cancel_evt.set()
            self.status_var.set("Cancelling…")

    def _search_done(self, rep):
        self.report = rep
        p, t = rep["prefix"], rep["total"]
        ids = rep["cluster_ids"]
        self._set_avail_columns(ids)
        self.tab_data["avail"] = [((r["number"], r["status"], *[r["per"][i] for i in ids], r["details"]),
                                   r["status"], r) for r in rep["avail"]]
        self.tab_data["dn"] = [((r["location"], r["pattern"], r["pt_disp"], r["descr"], r["alert"], r["devices"]),
                                "", r) for r in rep["dn"]]
        for key in ("route", "translation"):
            self.tab_data[key] = [((r["location"], r["pattern"], r["pt_disp"], r["descr"]), "", r) for r in rep[key]]
        self.tab_data["other"] = [((r["location"], r["pattern"], r["pt_disp"], r["usage"], r["descr"]), "", r)
                                  for r in rep["other"]]
        self.tab_data["wildcard"] = [((r["location"], r["pattern"], r["pt_disp"], r["usage"], r["descr"],
                                       r["matched"], r["overlapped"], r["example"]), "", r)
                                     for r in sorted(rep["wildcard"], key=lambda x: -x["matched"])]
        self.tab_data["fwd"] = [((r["location"], r["dn"], r["pt_disp"], r["descr"], r["dest"],
                                  fwd_match(r["dest"], p, t)), "", r) for r in rep["fwd"]]
        self.tab_data["busy"] = [((r["location"], r["dn"], r["pt_disp"], r["descr"], r["type"], r["dest"],
                                   fwd_match(r["dest"], p, t)), "", r) for r in rep["busy"]]
        self.tab_data["css"] = [((r["location"], r["css"], r["pt_disp"], r["order"]), "", r)
                                for r in rep["css"]]
        for i, key in enumerate(self.tab_keys):
            n = len(self.tab_data[key])
            self.nb.tab(i, text=TABS[key][0] + (f" ({n})" if key != "avail" else ""))
        self._paint_chips()
        self.nb.select(0)
        self._on_tab()
        c = rep["counts"]
        scope_bits = []
        if rep.get("target_partition"):
            scope_bits.append(f"PT {rep['target_partition']}")
        if rep.get("target_css"):
            scope_bits.append(f"CSS {rep['target_css']}")
        scope = f"  ·  scope: {', '.join(scope_bits)}" if scope_bits else ""
        text = (f"Done: {len(rep['avail']):,} candidates for {p} ({t} digits)  ·  {rep['n_prefix']} route-plan rows"
                f"{scope}  ·  USED {c['USED']}  ·  CHECK {c['CHECK']}  ·  OTHER PT {c['OTHER PT']}  ·  FREE {c['FREE']}")
        if rep["skipped_at"]:
            text += f"  ·  {rep['skipped_at']} @-patterns not evaluated"
        if rep["warnings"]:
            text += f"  ·  ⚠ {len(rep['warnings'])} warning(s)"
            messagebox.showwarning(APP_TITLE, "Search finished with warnings:\n\n" + "\n".join(rep["warnings"]))
        self.status_var.set(text)
        self._set_detail("Select a row to see full details. Ctrl+C copies selected rows, Ctrl+F jumps to Filter.")

    def on_export(self):
        if not self.report:
            return
        key = self._current_key()
        rows = self._visible(key)
        title = TABS[key][0].replace(" / ", "_").replace(" ", "_").lower()
        path = filedialog.asksaveasfilename(
            title="Export CSV", defaultextension=".csv",
            initialfile=f"{title}_{self.report['prefix']}_{self.report['total']}d.csv",
            filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                tree = self.trees[key]
                w.writerow([tree.heading(c, "text") for c in tree["columns"]])
                for values, _tag, payload in rows:
                    if key == "avail":   # full reasons, not the truncated grid text
                        values = values[:-1] + (" | ".join(payload["full"]),)
                    w.writerow(values)
        except OSError as exc:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n{exc}")
            return
        self.status_var.set(f"Exported {len(rows):,} rows from {TABS[key][0]} to {path}")

    def _on_close(self):
        if self.cancel_evt:
            self.cancel_evt.set()
        self.destroy()


def main():
    if sys.platform == "win32":          # crisp text on high-DPI / scaled displays
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass
    if requests is None:
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(APP_TITLE, "The 'requests' package is missing.\n\nRun:  python -m pip install requests")
        return
    App().mainloop()


if __name__ == "__main__":
    main()
