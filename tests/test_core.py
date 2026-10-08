"""Offline tests: pattern engine, availability logic, config handling, AXL parsing.
No CUCM needed - AXL responses are faked."""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dn_scout as m  # noqa: E402

CX = threading.Event()


def hits(pattern, prefix, total):
    return m.pattern_hits(m.compile_pattern(pattern), prefix, total, CX)


# ---------------------------------------------------------------- patterns
def test_exact_wildcard_match():
    assert hits("5405XX", "540506", 6) == {"540506": "match"}


def test_shorter_pattern_is_overlap():
    h = hits("54XX", "5405", 6)
    assert len(h) == 100 and set(h.values()) == {"overlap"}


def test_longer_pattern_is_overlap():
    h = hits("5405XXX", "5405", 6)
    assert len(h) == 100 and set(h.values()) == {"overlap"}


def test_unrelated_pattern_ignored():
    assert hits("[6-9]XXXXX", "5405", 6) == {}


def test_ranges_and_negation():
    assert len(hits("5405[0-4]X", "5405", 6)) == 50
    neg = hits("5405[^0-4]X", "5405", 6)
    assert len(neg) == 50 and "540550" in neg and "540540" not in neg


def test_bang_and_dot():
    assert set(hits("54!", "5405", 6).values()) == {"match"}
    assert set(hits("5405.0X", "5405", 6)) == {f"54050{i}" for i in range(10)}


def test_question_mark_quantifier():
    h = hits("54051?", "5405", 6)
    assert h["540511"] == "match" and h["540510"] == "overlap"


def test_at_patterns_skipped_and_literal_detection():
    assert m.compile_pattern("9.@") is None
    assert m.literal_of_tokens(m.compile_pattern("5405.06")) == "540506"


# ---------------------------------------------------------------- availability
class FakeClient(m.AxlClient):
    def __init__(self, name, data):  # noqa: D401 - no network
        self.name, self.host, self.version, self.data = name, "fake", "12.5", data

    def sql(self, query):
        if "SKIP 0" not in query:
            return []
        if "FROM callingsearchspace css" in query and "callingsearchspacemember" not in query:
            return self.data.get("callingsearchspace_only", [])
        for key, rows in self.data.items():
            if key in query:
                return rows
        return []


def row(pkid, pattern, pt, descr, enum, usage):
    return {"pkid": pkid, "dnpattern": pattern, "ptname": pt, "descr": descr,
            "usageenum": enum, "usagename": usage, "alertname": ""}


CL1 = {
    "alertingname": [
        row("a", "540506", "PT-INTERNAL", "Front Desk", "2", "Device"),
        row("b", "540507", "PT-OTHER", "Lab", "2", "Device"),
        row("c", "5405091", "PT-INTERNAL", "Overflow", "5", "Route"),
        row("d", "540508", "", "xform", "20", "Calling Party Transformation"),
    ],
    "LIKE '%X%'": [row("w", "54051X", "PT-XLATE", "Legacy", "3", "Translation"),
                   row("z", "9.@", "PT-PSTN", "", "5", "Route")],
    "devicenumplanmap": [{"npk": "a", "devname": "SEP00AABBCCDD01"}],
    "callforwarddynamic": [{"dnpattern": "5000", "ptname": "PT-INTERNAL", "descr": "", "dest": "540520"}],
    "cfbdestination": [{"dnpattern": "5001", "ptname": "PT-INTERNAL", "descr": "", "cfb": "", "cfbint": "",
                        "cfna": "540530", "cfnaint": "", "cfur": "", "cfurint": ""}],
}


def report(target=""):
    cfg = dict(m.DEFAULT_CONFIG)
    results = [m.search_cluster(FakeClient("CL1", CL1), "5405", 6, cfg, CX, lambda s: None),
               m.search_cluster(FakeClient("CL2", {}), "5405", 6, cfg, CX, lambda s: None)]
    return m.build_report(results, "5405", 6, target, True, CX)


def test_statuses():
    a = {r["number"]: r for r in report()["avail"]}
    assert a["540506"]["status"] == "USED" and a["540506"]["per"] == {"CL1": "USED", "CL2": "FREE"}
    assert a["540508"]["status"] == "FREE"            # transformations don't block
    assert a["540509"]["status"] == "CHECK"           # longer route pattern overlap
    assert a["540515"]["status"] == "CHECK"           # wildcard coverage
    assert a["540520"]["status"] == "CHECK"           # CFA target
    assert a["540530"]["status"] == "CHECK"           # CFNA target
    assert a["540599"]["status"] == "FREE"


def test_target_partition():
    a = {r["number"]: r for r in report("PT-INTERNAL")["avail"]}
    assert a["540506"]["status"] == "USED"
    assert a["540507"]["status"] == "OTHER PT"


def test_counts_and_devices():
    rep = report()
    assert sum(rep["counts"].values()) == 100
    assert rep["skipped_at"] == 1
    assert rep["dn"][0]["devices"] == "SEP00AABBCCDD01"


# ---------------------------------------------------------------- config
def test_legacy_config_and_duplicates():
    out = m.normalize_clusters({"UC": {"host": "10.0.0.1"}, "CC": {"host": "10.0.0.2", "axl_version": "14"}})
    assert [c["id"] for c in out] == ["UC", "CC"]
    try:
        m.normalize_clusters([{"id": "A"}, {"id": "a"}])
        raise AssertionError("duplicate ids accepted")
    except m.ConfigError:
        pass


def test_placeholders_are_inactive():
    cfg = {"clusters": m.normalize_clusters(m.DEFAULT_CONFIG["clusters"])}
    assert m.active_clusters(cfg) == []


def test_short_axl_version_normalized():
    cfg = {"clusters": m.normalize_clusters([{"id": "CL1", "host": "10.0.0.1", "axl_version": "14"}]),
           "timeout_seconds": 5}
    assert m.make_client(cfg, "CL1", "u", "p", False).version == "14.0"


# ---------------------------------------------------------------- AXL parsing
def test_fault_message_extracted():
    fault = (b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
             b'<soapenv:Fault><faultcode>x</faultcode><faultstring>A syntax error has occurred.</faultstring>'
             b'</soapenv:Fault></soapenv:Body></soapenv:Envelope>')
    assert m.AxlClient._fault(fault) == "A syntax error has occurred."


def test_version_fallback_on_599():
    ok = (b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
          b'<r><return><row><n>1</n></row></return></r></soapenv:Body></soapenv:Envelope>')

    class Resp:
        def __init__(self, code, content):
            self.status_code, self.content = code, content

    def post(url, data=None, headers=None, timeout=None):
        return Resp(200, ok) if b"/API/14.0" in data else Resp(599, b"Unsupported version")

    m.time.sleep = lambda s: None
    client = m.AxlClient("CL2", "fake", "u", "p", "12.5")
    client.session.post = post
    assert client.sql("SELECT 1") == [{"n": "1"}] and client.version == "14.0"


def test_sql_literal_escapes_quotes():
    assert m.sql_literal("Sales'CSS") == "'Sales''CSS'"


def test_css_scope_filters_unreachable_partitions():
    data = dict(CL1)
    data["callingsearchspace_only"] = [{"cssname": "INTERNAL-CSS"}]
    data["callingsearchspacemember"] = [
        {"cssname": "INTERNAL-CSS", "ptname": "PT-INTERNAL", "sortorder": "1"},
    ]
    cfg = dict(m.DEFAULT_CONFIG)
    result = m.search_cluster(FakeClient("CL1", data), "5405", 6, cfg, CX, lambda s: None,
                              "INTERNAL-CSS")
    rep = m.build_report([result], "5405", 6, "", True, CX, "INTERNAL-CSS")
    a = {r["number"]: r for r in rep["avail"]}
    assert a["540506"]["status"] == "USED"       # PT-INTERNAL is in selected CSS
    assert a["540507"]["status"] == "OTHER PT"   # PT-OTHER is outside selected CSS
    assert a["540515"]["status"] == "OTHER PT"   # wildcard PT-XLATE is outside selected CSS
    assert rep["css"][0]["css"] == "INTERNAL-CSS"


def test_null_partition_is_reachable_through_css():
    cr = {"name": "CL1", "prefix_rows": [m.norm_row(
              row("n", "540508", "", "Null PT", "2", "Device"), "CL1")],
          "wild_rows": [], "devices": {}, "cfa": [], "busy": [],
          "css_rows": [], "css_partitions": {"pt-internal"}, "css_requested": "INTERNAL-CSS",
          "css_found": True, "warnings": [], "skipped_at": 0}
    rep = m.build_report([cr], "540508", 6, "", True, CX, "INTERNAL-CSS")
    assert rep["avail"][0]["status"] == "USED"


def test_503_retries_without_schema_fallback():
    ok = (b'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
          b'<r><return><row><n>1</n></row></return></r></soapenv:Body></soapenv:Envelope>')

    class Resp:
        def __init__(self, code, content, headers=None):
            self.status_code, self.content, self.headers = code, content, headers or {}

    calls = []

    def post(url, data=None, headers=None, timeout=None):
        calls.append(data)
        return Resp(503, b"Service Unavailable", {"Retry-After": "0"}) if len(calls) == 1 else Resp(200, ok)

    old_sleep = m.time.sleep
    m.time.sleep = lambda s: None
    try:
        client = m.AxlClient("CL1", "fake", "u", "p", "12.5", retry_attempts=3, retry_base_seconds=0)
        client.session.post = post
        assert client.sql("SELECT 1") == [{"n": "1"}]
        assert client.version == "12.5"
        assert len(calls) == 2
        assert all(b"/API/12.5" in body for body in calls)
    finally:
        m.time.sleep = old_sleep


def test_public_diag_redaction():
    import axl_diag as d
    old_mode = d.PUBLIC_MODE
    old_values = set(d.SENSITIVE_VALUES)
    try:
        d.PUBLIC_MODE = True
        d.SENSITIVE_VALUES.clear()
        d.SENSITIVE_VALUES.update({"cucm-pub.example.com", "axluser", "5405"})
        text = d.redact("user=axluser host=cucm-pub.example.com ip=10.2.3.4 prefix=5405 https://other.internal/path")
        assert "axluser" not in text
        assert "cucm-pub.example.com" not in text
        assert "10.2.3.4" not in text
        assert "5405" not in text
        assert "https://<host>/path" in text
    finally:
        d.PUBLIC_MODE = old_mode
        d.SENSITIVE_VALUES.clear()
        d.SENSITIVE_VALUES.update(old_values)


def test_existing_empty_css_is_valid_scope():
    data = dict(CL1)
    data["callingsearchspace_only"] = [{"cssname": "EMPTY-CSS"}]
    data["callingsearchspacemember"] = []
    cfg = dict(m.DEFAULT_CONFIG)
    result = m.search_cluster(FakeClient("CL1", data), "5405", 6, cfg, CX, lambda s: None, "EMPTY-CSS")
    assert result["css_found"] is True
    assert result["css_partitions"] == set()
    rep = m.build_report([result], "5405", 6, "", True, CX, "EMPTY-CSS")
    a = {r["number"]: r for r in rep["avail"]}
    assert a["540506"]["status"] == "OTHER PT"


def test_public_branding_and_entrypoint():
    assert m.APP_NAME == "DN Scout"
    assert m.APP_TITLE == "DN Scout v1.1.0"
