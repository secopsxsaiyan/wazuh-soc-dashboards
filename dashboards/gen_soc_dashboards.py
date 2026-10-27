#!/usr/bin/env python3
"""Generate the SOC overview dashboards for Wazuh 4.x / OpenSearch Dashboards 2.x (stdlib only).

Writes two saved-object exports (NDJSON) into the output directory:

  wazuh_soc_dashboards.ndjson            fleet-wide SOC views on the stock Wazuh index patterns
                                         (wazuh-alerts-*, wazuh-monitoring-*, wazuh-statistics-*,
                                         wazuh-states-vulnerabilities-*)
  wazuh_soc_inventory_dashboard.ndjson   attack-surface view on the IT-hygiene state indices
                                         (wazuh-states-inventory-*-*, Wazuh 4.13+)
  index_patterns.ndjson                  the index patterns both files reference, for installs
                                         that do not have them yet (import only what is missing)

Every visualization references its index pattern by the ID the Wazuh dashboard plugin gives the
patterns it creates (the ID equals the pattern title, e.g. "wazuh-alerts-*"). Installs that lack
one of those patterns (plain OpenSearch Dashboards, statistics job disabled, pre-4.13 inventory)
can import index_patterns.ndjson first.

Scope rule: nothing here duplicates the per-product dashboards that ship with the UniFi, Proxmox
VE and TrueNAS packs. Product-specific panels live in those packs; this board covers the
fleet-level view, stock Wazuh modules, and the cross-product packs (threat detection, FIM
escalation, Windows, MISP IOC) that have no dashboard of their own. Panels that would otherwise
pick up product events exclude them with PRODUCT_PACKS_EXCLUDE.

Usage:  python3 gen_soc_dashboards.py [--out-dir DIR]
"""
import argparse
import json
import os

OSD_VERSION = "2.16.0"   # panel schema version; imports into OSD 2.x / Wazuh dashboard 4.x

# ---- stock index-pattern IDs (created by the Wazuh dashboard health check; ID == title) ----
ALERTS = "wazuh-alerts-*"
MONITORING = "wazuh-monitoring-*"
STATS = "wazuh-statistics-*"
VULN = "wazuh-states-vulnerabilities-*"
INV_PORTS = "wazuh-states-inventory-ports-*"
INV_USERS = "wazuh-states-inventory-users-*"
INV_SERVICES = "wazuh-states-inventory-services-*"
INV_PACKAGES = "wazuh-states-inventory-packages-*"

# Saved-object ID prefix. Pack dashboards use "uni-", "pve-", "tn-" and their own dashboard IDs;
# everything here starts with "socov-" so importing both never overwrites anything.
PFX = "socov-"

# Product packs that ship their own dashboard. Their events are excluded from the
# cross-source panels below so the same signal is not charted twice.
PRODUCT_PACKS_EXCLUDE = "not rule.groups:(unifi or proxmox or truenas or npm_access or npm_error or npm_cert)"

REPO = "https://github.com/secopsxsaiyan"
PACK_DASHBOARDS = [
    # (pack repo, dashboard saved-object id in that pack, dashboard title)
    ("wazuh-unifi", "unifi-threats", "UniFi Threats"),
    ("wazuh-proxmox", "proxmox-security-threats", "Proxmox VE Security & Threats"),
    ("wazuh-truenas", "truenas-audit-threats", "TrueNAS Audit & Threats"),
    ("wazuh-nginx-proxy-manager", "npm-web-threats", "Nginx Proxy Manager - Web Threats"),
]

# Rule IDs from the public packs used in queries (validated by tools/validate_saved_objects.py).
FIM_ESCALATION_IDS = ["100035", "100036", "100037", "100038", "100039", "101440", "101441"]
BOOT_INTEGRITY_IDS = ["101430"]                                   # wazuh-threat-detection
EXECVE_IDS = ["101400", "101403", "101404"]                       # wazuh-threat-detection
SURICATA_IDS = ["101451", "101452", "101453"]                     # wazuh-threat-detection
SPAMHAUS_IDS = ["100234", "100235", "100236", "100237"]           # wazuh-threat-detection
ENROLLMENT_IDS = ["101501", "101502"]                             # wazuh-threat-detection
HOST_TAMPER_IDS = ["101435", "100362"]                            # clock change, rapid sudo
WINDOWS_IDS = ["100450", "100451", "100452"]                      # wazuh-windows
MISP_IP_IDS = ["100210", "100211", "100216", "100217", "100218"]
MISP_FILE_IDS = ["100212", "100213", "100215", "100232", "100233"]
MISP_URL_IDS = ["100227", "100228"]
MISP_DOMAIN_IDS = ["100214"]
MISP_JA3_IDS = ["100229", "100230", "100231"]
MISP_ALL_IDS = MISP_IP_IDS + MISP_FILE_IDS + MISP_URL_IDS + MISP_DOMAIN_IDS + MISP_JA3_IDS
THREAT_HIGH_IDS = ["101400", "101403", "101404", "101430", "101501", "100236", "101451", "101452"]


def ids_q(ids):
    """KQL clause matching any of the given rule IDs."""
    return "rule.id:(%s)" % " or ".join(ids)


# ---------------------------------------------------------------------------------------------
# saved-object builders
# ---------------------------------------------------------------------------------------------
class Builder:
    def __init__(self):
        self.objects = []

    @staticmethod
    def _search_source(query):
        return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [],
                           "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})

    def viz(self, vid, title, idx, vistype, aggs, params, query="", desc=""):
        # Data tables only split rows when bucket aggs use schema "bucket"; "segment"/"group"
        # (right for pie/xy) make a table show the bare metric. Force "bucket" for tables.
        # Secondary terms columns get a "missing" bucket, otherwise a row disappears when the
        # column's field is absent (e.g. no GeoLocation for private source addresses).
        if vistype == "table":
            first_bucket = True
            for agg in aggs:
                if agg.get("type") in ("terms", "date_histogram", "histogram", "range", "filters") \
                        and agg.get("schema") in ("segment", "group"):
                    agg["schema"] = "bucket"
                if agg.get("schema") == "bucket":
                    if agg["type"] == "terms" and not first_bucket:
                        agg["params"]["missingBucket"] = True
                        agg["params"]["missingBucketLabel"] = "-"
                    first_bucket = False
        self.objects.append({
            "id": PFX + vid, "type": "visualization",
            "attributes": {
                "title": title,
                "visState": json.dumps({"title": title, "type": vistype, "aggs": aggs, "params": params}),
                "uiStateJSON": "{}", "description": desc, "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": self._search_source(query)},
            },
            "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                            "type": "index-pattern", "id": idx}],
        })
        return PFX + vid

    def markdown(self, vid, title, text):
        params = {"fontSize": 12, "openLinksInNewTab": False, "markdown": text}
        self.objects.append({
            "id": PFX + vid, "type": "visualization",
            "attributes": {
                "title": title,
                "visState": json.dumps({"title": title, "type": "markdown", "aggs": [], "params": params}),
                "uiStateJSON": "{}", "description": "", "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []})},
            },
            "references": [],
        })
        return PFX + vid

    def controls(self, vid, title, idx, controls):
        """Input-control panel (agent / level pickers) - no hard-coded agent names."""
        ctl, refs = [], []
        for i, (field, label, ctype) in enumerate(controls):
            ref = "control_%d_index_pattern" % i
            if ctype == "list":
                options = {"type": "terms", "multiselect": True, "dynamicOptions": True,
                           "size": 50, "order": "desc"}
            else:
                options = {"decimalPlaces": 0, "step": 1}
            ctl.append({"id": str(i + 1), "fieldName": field, "label": label, "type": ctype,
                        "options": options, "parent": "", "indexPatternRefName": ref})
            refs.append({"name": ref, "type": "index-pattern", "id": idx})
        params = {"controls": ctl, "updateFiltersOnChange": True, "useTimeFilter": True,
                  "pinFilters": False}
        self.objects.append({
            "id": PFX + vid, "type": "visualization",
            "attributes": {
                "title": title,
                "visState": json.dumps({"title": title, "type": "input_control_vis", "aggs": [],
                                        "params": params}),
                "uiStateJSON": "{}", "description": "", "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []})},
            },
            "references": refs,
        })
        return PFX + vid

    def dashboard(self, did, title, panels, desc=""):
        """panels: list of vid or (vid, width, height). Simple left-to-right flow layout
        on the 48-column grid."""
        pj, refs = [], []
        x = y = row_h = 0
        for i, p in enumerate(panels):
            vid, w, h = (p, 24, 15) if isinstance(p, str) else p
            if x + w > 48:
                x, y, row_h = 0, y + row_h, 0
            pidx = str(i)
            pj.append({"version": OSD_VERSION,
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pidx},
                       "panelIndex": pidx, "embeddableConfig": {}, "panelRefName": "panel_" + pidx})
            refs.append({"name": "panel_" + pidx, "type": "visualization", "id": vid})
            x += w
            row_h = max(row_h, h)
        self.objects.append({
            "id": PFX + did, "type": "dashboard",
            "attributes": {
                "title": title, "hits": 0, "description": desc,
                "panelsJSON": json.dumps(pj),
                "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
                "version": 1, "timeRestore": False,
                "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                    {"query": {"language": "kuery", "query": ""}, "filter": []})},
            },
            "references": refs,
        })
        return PFX + did


# ---------------------------------------------------------------------------------------------
# agg / param builders
# ---------------------------------------------------------------------------------------------
def a_count(aid="1"):
    return {"id": aid, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def a_avg(aid, field):
    return {"id": aid, "enabled": True, "type": "avg", "schema": "metric", "params": {"field": field}}


def a_max(aid, field):
    return {"id": aid, "enabled": True, "type": "max", "schema": "metric", "params": {"field": field}}


def a_cardinality(aid, field):
    return {"id": aid, "enabled": True, "type": "cardinality", "schema": "metric",
            "params": {"field": field}}


def a_terms(aid, field, size=10, schema="segment", order_by="1"):
    return {"id": aid, "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": order_by, "order": "desc", "size": size,
                       "otherBucket": False, "otherBucketLabel": "Other",
                       "missingBucket": False, "missingBucketLabel": "Missing"}}


def a_filters(aid, named_queries, schema="segment"):
    return {"id": aid, "enabled": True, "type": "filters", "schema": schema,
            "params": {"filters": [{"input": {"query": q, "language": "kuery"}, "label": label}
                                   for label, q in named_queries]}}


def a_datehist(aid, field="@timestamp", schema="segment"):
    return {"id": aid, "enabled": True, "type": "date_histogram", "schema": schema,
            "params": {"field": field, "useNormalizedEsInterval": True, "interval": "auto",
                       "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}


def p_table(per_page=15):
    return {"perPage": per_page, "showPartialRows": False, "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None}, "showTotal": True,
            "totalFunc": "sum", "percentageCol": ""}


def p_metric(label="", font=42):
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 1000000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                 "subText": label, "fontSize": font}}}


def p_pie(donut=True):
    return {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
            "isDonut": donut, "labels": {"show": False, "values": True, "last_level": True,
                                         "truncate": 100}}


def p_xy(vistype, series, stacked=False, y_title="Count"):
    """series = list of (metric_agg_id, label). vistype: area | line | histogram."""
    mode = "stacked" if stacked else "normal"
    series_params = [{"show": True, "type": vistype, "mode": mode, "data": {"label": lbl, "id": mid},
                      "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2,
                      "showCircles": True, "interpolate": "linear"} for mid, lbl in series]
    return {"type": vistype, "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "style": {}, "scale": {"type": "linear"},
                              "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                           "position": "left", "show": True, "style": {},
                           "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": y_title}}],
            "seriesParams": series_params, "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "times": [], "addTimeMarker": False, "labels": {},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                              "color": "#E7664C"}}


def _and(*clauses):
    return " and ".join("(%s)" % c for c in clauses if c)


# ---------------------------------------------------------------------------------------------
# dashboards
# ---------------------------------------------------------------------------------------------
def build_main(b):
    agent_ctl = b.controls("ctl-alerts", "SOC filters: agent / level", ALERTS,
                           [("agent.name", "Agent", "list"), ("rule.level", "Rule level", "range")])

    # 1) Triage cockpit ------------------------------------------------------------------------
    pack_filters = [
        ("wazuh-unifi", "rule.groups:unifi"),
        ("wazuh-proxmox", "rule.groups:proxmox"),
        ("wazuh-truenas", "rule.groups:truenas"),
        ("wazuh-nginx-proxy-manager", "rule.groups:(npm_access or npm_error or npm_cert)"),
        ("wazuh-threat-detection", "rule.groups:soc_threat_detection"),
        ("wazuh-fim-escalation", ids_q(FIM_ESCALATION_IDS)),
        ("wazuh-windows", ids_q(WINDOWS_IDS)),
        ("wazuh-misp-ioc", "rule.groups:misp"),
    ]
    links = "\n".join("- **%s** - [open dashboard](/app/dashboards#/view/%s) · [pack](%s/%s)"
                      % (title, did, REPO, repo) for repo, did, title in PACK_DASHBOARDS)
    triage = [
        (agent_ctl, 48, 6),
        (b.viz("triage-timeline", "SOC: alerts over time by level", ALERTS, "area",
               [a_count("1"), a_datehist("2"), a_terms("3", "rule.level", 8, schema="group")],
               p_xy("area", [("1", "Count")], stacked=True, y_title="Alerts")), 24, 15),
        (b.viz("triage-kpi-gate", "SOC: alerts at level 10+ (triage gate)", ALERTS, "metric",
               [a_count("1")], p_metric("level >= 10"), query="rule.level >= 10"), 12, 15),
        (b.viz("triage-kpi-crit", "SOC: alerts at level 12+ (critical)", ALERTS, "metric",
               [a_count("1")], p_metric("level >= 12"), query="rule.level >= 12"), 12, 15),
        (b.viz("triage-gate-rules", "SOC: level 10+ alerts by rule and agent", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.id", 20), a_terms("3", "rule.description", 1),
                a_terms("4", "agent.name", 5)], p_table(), query="rule.level >= 10"), 48, 15),
        (b.viz("triage-toprules", "SOC: top rules (all levels)", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.id", 15), a_terms("3", "rule.description", 1),
                a_terms("4", "rule.level", 1)], p_table()), 24, 15),
        (b.viz("triage-agents", "SOC: alerts by agent", ALERTS, "pie",
               [a_count("1"), a_terms("2", "agent.name", 10)], p_pie()), 24, 15),
        (b.viz("triage-mitre-tactics", "SOC: MITRE ATT&CK tactics", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.mitre.tactic", 15)], p_table(),
               query="rule.mitre.tactic:*"), 16, 15),
        (b.viz("triage-mitre-ids", "SOC: MITRE ATT&CK technique IDs", ALERTS, "histogram",
               [a_count("1"), a_terms("2", "rule.mitre.id", 15)],
               p_xy("histogram", [("1", "Count")], y_title="Alerts"),
               query="rule.mitre.id:*"), 32, 15),
        (b.viz("triage-mitre-techniques", "SOC: MITRE ATT&CK techniques by tactic", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.mitre.technique", 20),
                a_terms("3", "rule.mitre.tactic", 5)], p_table(), query="rule.mitre.id:*"), 48, 15),
        # the single cross-product row: alert counts per pack + links to the pack dashboards
        (b.viz("triage-packs", "SOC: alerts by detection pack", ALERTS, "table",
               [a_count("1"), a_filters("2", pack_filters)], p_table(10)), 24, 15),
        (b.markdown("triage-pack-links", "SOC: product pack dashboards",
                    "Product-specific views ship with their own packs:\n\n" + links +
                    "\n\nDashboard links assume the default base path; import each pack's "
                    "ndjson first."), 24, 15),
    ]
    b.dashboard("triage", "SOC Overview - Triage Cockpit", triage,
                "Fleet-wide landing view: alert volume by level, the L10 triage gate, top rules and "
                "agents, MITRE ATT&CK breakdown, and alert counts per detection pack.")

    # 2) Authentication (Linux / Windows hosts) -------------------------------------------------
    auth_q = _and("rule.groups:(authentication_success or authentication_failed or "
                  "authentication_failures or sudo)", PRODUCT_PACKS_EXCLUDE)
    fail_q = _and("rule.groups:(authentication_failed or authentication_failures)",
                  PRODUCT_PACKS_EXCLUDE)
    auth = [
        (agent_ctl, 48, 6),
        (b.viz("auth-timeline", "SOC auth: events over time by group", ALERTS, "area",
               [a_count("1"), a_datehist("2"), a_filters("3", [
                   ("success", "rule.groups:authentication_success"),
                   ("failed", "rule.groups:authentication_failed"),
                   ("repeated failures", "rule.groups:authentication_failures"),
                   ("sudo", "rule.groups:sudo")], schema="group")],
               p_xy("area", [("1", "Count")], stacked=True, y_title="Events"), query=auth_q), 32, 15),
        (b.viz("auth-kpi-fail", "SOC auth: authentication failures", ALERTS, "metric",
               [a_count("1")], p_metric("auth failed"), query=fail_q), 16, 15),
        (b.viz("auth-fail-src", "SOC auth: failure source IPs", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.srcip", 20),
                a_terms("3", "GeoLocation.country_name", 1), a_terms("4", "agent.name", 3)],
               p_table(), query=_and(fail_q, "data.srcip:*")), 24, 15),
        (b.viz("auth-linux-users", "SOC auth: Linux accounts targeted (dstuser)", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.dstuser", 15), a_terms("3", "rule.groups", 3)],
               p_table(), query=_and(auth_q, "data.dstuser:*")), 24, 15),
        (b.viz("auth-win-users", "SOC auth: Windows logons by target account", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.win.eventdata.targetUserName", 15),
                a_terms("3", "data.win.system.eventID", 4), a_terms("4", "agent.name", 3)],
               p_table(), query=_and(auth_q, "rule.groups:windows")), 24, 15),
        (b.viz("auth-sudo", "SOC auth: sudo activity by agent and user", ALERTS, "table",
               [a_count("1"), a_terms("2", "agent.name", 10), a_terms("3", "data.srcuser", 5),
                a_terms("4", "data.dstuser", 3)], p_table(),
               query=_and("rule.groups:sudo", PRODUCT_PACKS_EXCLUDE)), 24, 15),
        (b.viz("auth-brute", "SOC auth: brute-force / repeated-failure alerts", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.description", 10), a_terms("3", "agent.name", 5)],
               p_table(), query=_and("rule.groups:(authentication_failures or brute_force)",
                                     PRODUCT_PACKS_EXCLUDE)), 48, 15),
    ]
    b.dashboard("auth", "SOC Overview - Authentication (Linux & Windows hosts)", auth,
                "Host authentication across agents: sshd/PAM/sudo and Windows logons. UniFi, "
                "Proxmox VE and TrueNAS logins are excluded - see those packs' dashboards.")

    # 3) File integrity monitoring ---------------------------------------------------------------
    fim_q = "rule.groups:syscheck and syscheck.path:*"
    esc_q = ids_q(FIM_ESCALATION_IDS + BOOT_INTEGRITY_IDS)
    fim = [
        (agent_ctl, 48, 6),
        (b.viz("fim-timeline", "SOC FIM: changes over time by event", ALERTS, "area",
               [a_count("1"), a_datehist("2"), a_terms("3", "syscheck.event", 4, schema="group")],
               p_xy("area", [("1", "Count")], stacked=True, y_title="Changes"), query=fim_q), 32, 15),
        (b.viz("fim-kpi-esc", "SOC FIM: sensitive-path escalations", ALERTS, "metric",
               [a_count("1")], p_metric("escalated"), query=esc_q), 16, 15),
        (b.viz("fim-esc", "SOC FIM: sensitive-path escalations (fim-escalation + /boot)", ALERTS,
               "table", [a_count("1"), a_terms("2", "rule.description", 10),
                         a_terms("3", "syscheck.path", 10), a_terms("4", "agent.name", 3)],
               p_table(), query=esc_q), 48, 15),
        (b.viz("fim-top-paths", "SOC FIM: most-changed paths", ALERTS, "table",
               [a_count("1"), a_terms("2", "syscheck.path", 25)], p_table(), query=fim_q), 24, 15),
        (b.viz("fim-by-agent", "SOC FIM: changes by agent and event", ALERTS, "table",
               [a_count("1"), a_terms("2", "agent.name", 10), a_terms("3", "syscheck.event", 4)],
               p_table(), query=fim_q), 24, 15),
        (b.viz("fim-users", "SOC FIM: changes by owning user (after)", ALERTS, "pie",
               [a_count("1"), a_terms("2", "syscheck.uname_after", 10)], p_pie(),
               query=_and(fim_q, "syscheck.uname_after:*")), 24, 15),
        (b.viz("fim-esc-mitre", "SOC FIM: escalations by MITRE technique", ALERTS, "pie",
               [a_count("1"), a_terms("2", "rule.mitre.technique", 10)], p_pie(),
               query=esc_q), 24, 15),
    ]
    b.dashboard("fim", "SOC Overview - File Integrity Monitoring", fim,
                "Syscheck adds/modifies/deletes across all agents, plus the wazuh-fim-escalation "
                "rules and the wazuh-threat-detection /boot rule.")

    # 4) Vulnerability detection (state index) ---------------------------------------------------
    vuln = [
        (b.viz("vuln-severity", "SOC vulns: findings by severity", VULN, "pie",
               [a_count("1"), a_terms("2", "vulnerability.severity", 6)], p_pie()), 16, 15),
        (b.viz("vuln-kpi-crit", "SOC vulns: Critical findings", VULN, "metric",
               [a_count("1")], p_metric("Critical"), query="vulnerability.severity:Critical"), 16, 15),
        (b.viz("vuln-kpi-high", "SOC vulns: High findings", VULN, "metric",
               [a_count("1")], p_metric("High"), query="vulnerability.severity:High"), 16, 15),
        (b.viz("vuln-by-host", "SOC vulns: findings by agent and severity", VULN, "table",
               [a_count("1"), a_terms("2", "agent.name", 15), a_terms("3", "vulnerability.severity", 5)],
               p_table()), 24, 15),
        (b.viz("vuln-by-pkg", "SOC vulns: top vulnerable packages (max CVSS)", VULN, "table",
               [a_max("1", "vulnerability.score.base"), a_terms("2", "package.name", 15),
                a_cardinality("3", "agent.id")], p_table()), 24, 15),
        (b.viz("vuln-top-cves", "SOC vulns: top Critical/High CVEs", VULN, "table",
               [a_count("1"), a_terms("2", "vulnerability.id", 20), a_terms("3", "package.name", 1)],
               p_table(), query="vulnerability.severity:(Critical or High)"), 24, 15),
        (b.viz("vuln-unscored", "SOC vulns: unscored / pending-score findings", VULN, "table",
               [a_count("1"), a_terms("2", "vulnerability.id", 20), a_terms("3", "agent.name", 5)],
               p_table(), query='vulnerability.severity:"-" or vulnerability.score.base < 0'), 24, 15),
        (b.viz("vuln-timeline", "SOC vulns: findings by detection date", VULN, "area",
               [a_count("1"), a_datehist("2", "vulnerability.detected_at"),
                a_terms("3", "vulnerability.severity", 5, schema="group")],
               p_xy("area", [("1", "Count")], stacked=True, y_title="Findings")), 48, 15),
    ]
    b.dashboard("vuln", "SOC Overview - Vulnerability Detection", vuln,
                "Vulnerability-detector state (wazuh-states-vulnerabilities-*): severity, hosts, "
                "packages, top CVEs and findings still waiting for a score.")

    # 5) Configuration assessment (SCA) + rootcheck ----------------------------------------------
    sca_q = "rule.groups:sca and data.sca.check.result:*"
    rc_q = "rule.groups:rootcheck"
    sca = [
        (agent_ctl, 48, 6),
        (b.viz("sca-result", "SOC SCA: check results", ALERTS, "pie",
               [a_count("1"), a_terms("2", "data.sca.check.result", 5)], p_pie(), query=sca_q), 16, 15),
        (b.viz("sca-by-policy", "SOC SCA: results by policy", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.sca.policy", 10),
                a_terms("3", "data.sca.check.result", 3)], p_table(), query=sca_q), 32, 15),
        (b.viz("sca-fail-agent", "SOC SCA: failed checks by agent", ALERTS, "table",
               [a_count("1"), a_terms("2", "agent.name", 15), a_terms("3", "data.sca.policy", 3)],
               p_table(), query=_and(sca_q, "data.sca.check.result:failed")), 24, 15),
        (b.viz("sca-top-fail", "SOC SCA: top failing checks", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.sca.check.title", 20)], p_table(),
               query=_and(sca_q, "data.sca.check.result:failed")), 24, 15),
        (b.viz("sca-score", "SOC SCA: latest score by policy (min)", ALERTS, "table",
               [{"id": "1", "enabled": True, "type": "min", "schema": "metric",
                 "params": {"field": "data.sca.score"}},
                a_terms("2", "data.sca.policy", 10), a_terms("3", "agent.name", 10)],
               p_table(), query="rule.groups:sca and data.sca.score:*"), 48, 15),
        (b.viz("rootcheck-timeline", "SOC rootcheck: anomalies over time", ALERTS, "histogram",
               [a_count("1"), a_datehist("2"), a_terms("3", "agent.name", 5, schema="group")],
               p_xy("histogram", [("1", "Count")], stacked=True, y_title="Events"),
               query=rc_q), 24, 15),
        (b.viz("rootcheck-titles", "SOC rootcheck: findings by title and agent", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.title", 15), a_terms("3", "agent.name", 5)],
               p_table(), query=rc_q), 24, 15),
    ]
    b.dashboard("sca", "SOC Overview - Configuration Assessment & Rootcheck", sca,
                "SCA (CIS and custom policies) pass/fail across agents, plus rootcheck host-anomaly "
                "findings.")

    # 6) Threat detection (cross-pack: threat-detection + windows) ---------------------------------
    td = [
        (agent_ctl, 48, 6),
        (b.viz("td-kpi-high", "SOC threats: high-confidence host/network detections", ALERTS,
               "metric", [a_count("1")], p_metric("L12+ detections"), query=ids_q(THREAT_HIGH_IDS)),
         16, 15),
        (b.viz("td-timeline", "SOC threats: detections over time by rule", ALERTS, "histogram",
               [a_count("1"), a_datehist("2"), a_terms("3", "rule.id", 10, schema="group")],
               p_xy("histogram", [("1", "Count")], stacked=True, y_title="Alerts"),
               query=ids_q(EXECVE_IDS + BOOT_INTEGRITY_IDS + SURICATA_IDS + SPAMHAUS_IDS +
                           ENROLLMENT_IDS + HOST_TAMPER_IDS + WINDOWS_IDS)), 32, 15),
        (b.viz("td-execve", "SOC threats: reverse shell / audit tamper / miner (auditd execve)",
               ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.description", 10),
                a_terms("3", "data.audit.exe", 5), a_terms("4", "agent.name", 5)],
               p_table(), query=ids_q(EXECVE_IDS)), 48, 15),
        (b.viz("td-suricata", "SOC threats: Suricata IDS (malicious / ET threat / scan)", ALERTS,
               "table", [a_count("1"), a_terms("2", "data.alert.signature", 15),
                         a_terms("3", "data.src_ip", 3), a_terms("4", "data.dest_ip", 3)],
               p_table(), query=ids_q(SURICATA_IDS)), 48, 15),
        (b.viz("td-spamhaus", "SOC threats: Spamhaus DROP ranges allowed / logged in", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.id", 4), a_terms("3", "data.srcip", 10),
                a_terms("4", "data.dstip", 5)], p_table(), query=ids_q(SPAMHAUS_IDS)), 24, 15),
        (b.viz("td-enroll", "SOC threats: agent enrollment (wazuh-authd)", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.description", 5), a_terms("3", "agent.name", 5)],
               p_table(), query=ids_q(ENROLLMENT_IDS)), 24, 15),
        (b.viz("td-tamper", "SOC threats: clock changes and rapid sudo escalation", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.description", 5), a_terms("3", "agent.name", 5),
                a_terms("4", "data.srcuser", 3)], p_table(), query=ids_q(HOST_TAMPER_IDS)), 24, 15),
        (b.viz("td-windows", "SOC threats: Windows tunnelling / WSL", ALERTS, "table",
               [a_count("1"), a_terms("2", "rule.description", 5),
                a_terms("3", "data.win.system.computer", 5),
                a_terms("4", "data.win.eventdata.serviceName", 3)],
               p_table(), query=ids_q(WINDOWS_IDS)), 24, 15),
    ]
    b.dashboard("threats", "SOC Overview - Threat Detection (cross-pack)", td,
                "Detections from wazuh-threat-detection (auditd execve, /boot, Suricata, Spamhaus "
                "DROP, enrollment, clock/sudo) and wazuh-windows. Product-pack chains (UniFi IPS, "
                "TrueNAS audit config) stay on those packs' dashboards.")

    # 7) MISP IOC matches (all sources except the UniFi feed, which its pack already charts) ------
    ioc_base = _and(ids_q(MISP_ALL_IDS), "not decoder.name:unifi*")
    ioc = [
        (agent_ctl, 48, 6),
        (b.viz("ioc-kpi", "SOC IOC: MISP indicator matches", ALERTS, "metric",
               [a_count("1")], p_metric("IOC hits"), query=ioc_base), 16, 15),
        (b.viz("ioc-types", "SOC IOC: matches by indicator type", ALERTS, "pie",
               [a_count("1"), a_filters("2", [
                   ("IP", ids_q(MISP_IP_IDS)), ("file hash / name", ids_q(MISP_FILE_IDS)),
                   ("URL", ids_q(MISP_URL_IDS)), ("domain", ids_q(MISP_DOMAIN_IDS)),
                   ("JA3", ids_q(MISP_JA3_IDS))])], p_pie(), query=ioc_base), 32, 15),
        (b.viz("ioc-by-source", "SOC IOC: matches by agent and decoder", ALERTS, "table",
               [a_count("1"), a_terms("2", "agent.name", 10), a_terms("3", "decoder.name", 5),
                a_terms("4", "rule.id", 5)], p_table(), query=ioc_base), 48, 15),
        (b.viz("ioc-ip", "SOC IOC: IP indicator matches (non-UniFi sources)", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.srcip", 15), a_terms("3", "data.dstip", 5),
                a_terms("4", "GeoLocation.country_name", 1)], p_table(),
               query=_and(ids_q(MISP_IP_IDS), "not decoder.name:unifi*")), 24, 15),
        (b.viz("ioc-file", "SOC IOC: file hash / filename matches", ALERTS, "table",
               [a_count("1"), a_terms("2", "syscheck.path", 15), a_terms("3", "agent.name", 5)],
               p_table(), query=ids_q(MISP_FILE_IDS)), 24, 15),
        (b.viz("ioc-url", "SOC IOC: URL indicator matches", ALERTS, "table",
               [a_count("1"), a_terms("2", "data.url", 15), a_terms("3", "data.srcip", 5)],
               p_table(), query=ids_q(MISP_URL_IDS)), 24, 15),
        (b.viz("ioc-timeline", "SOC IOC: matches over time", ALERTS, "area",
               [a_count("1"), a_datehist("2"), a_terms("3", "rule.id", 8, schema="group")],
               p_xy("area", [("1", "hits")], stacked=True, y_title="IOC hits"), query=ioc_base), 24, 15),
    ]
    b.dashboard("ioc", "SOC Overview - MISP IOC Matches", ioc,
                "wazuh-misp-ioc matches (IP, file hash/name, URL, domain, JA3) from every source "
                "except the UniFi feed, which the UniFi Threats dashboard already covers.")

    # 8) Wazuh pipeline health (statistics index) -------------------------------------------------
    pipe = [
        (b.viz("pipe-throughput", "SOC pipeline: events received vs alerts written", STATS, "line",
               [a_avg("1", "analysisd.events_received"), a_avg("3", "analysisd.alerts_written"),
                a_datehist("2", "timestamp")],
               p_xy("line", [("1", "events received"), ("3", "alerts written")],
                    y_title="per interval")), 48, 15),
        (b.viz("pipe-dropped", "SOC pipeline: events dropped (max)", STATS, "metric",
               [a_max("1", "analysisd.events_dropped")], p_metric("max dropped")), 16, 12),
        (b.viz("pipe-alertq", "SOC pipeline: alerts queue usage (max)", STATS, "metric",
               [a_max("1", "analysisd.alerts_queue_usage")], p_metric("alerts queue")), 16, 12),
        (b.viz("pipe-eventq-kpi", "SOC pipeline: event queue usage (max)", STATS, "metric",
               [a_max("1", "analysisd.event_queue_usage")], p_metric("event queue")), 16, 12),
        (b.viz("pipe-queue", "SOC pipeline: event queue usage over time", STATS, "line",
               [a_max("1", "analysisd.event_queue_usage"), a_datehist("2", "timestamp")],
               p_xy("line", [("1", "event queue")], y_title="usage")), 48, 15),
    ]
    b.dashboard("pipeline", "SOC Overview - Wazuh Pipeline Health", pipe,
                "analysisd throughput, drops and queue saturation from wazuh-statistics-* "
                "(dropped events or a full queue mean alerts are being lost).")

    # 9) Agent health (monitoring index) ----------------------------------------------------------
    agents = [
        (b.viz("agents-kpi-active", "SOC agents: active agents (distinct)", MONITORING, "metric",
               [a_cardinality("1", "id")], p_metric("active agents"), query="status:active"), 16, 15),
        (b.viz("agents-kpi-down", "SOC agents: disconnected agents", MONITORING, "metric",
               [a_cardinality("1", "id")], p_metric("disconnected"), query="status:disconnected"),
         16, 15),
        (b.viz("agents-status", "SOC agents: status distribution", MONITORING, "pie",
               [a_count("1"), a_terms("2", "status", 5)], p_pie()), 16, 15),
        (b.viz("agents-table", "SOC agents: agents by status", MONITORING, "table",
               [a_count("1"), a_terms("2", "name", 50), a_terms("3", "status", 4)], p_table(20)), 24, 15),
        (b.viz("agents-timeline", "SOC agents: status over time", MONITORING, "line",
               [a_cardinality("1", "id"), a_datehist("2", "timestamp"),
                a_terms("3", "status", 4, schema="group")],
               p_xy("line", [("1", "agents")], y_title="agents")), 24, 15),
    ]
    b.dashboard("agents", "SOC Overview - Agent Health", agents,
                "Agent connection status from wazuh-monitoring-*: active vs disconnected / never "
                "connected / pending, per agent and over time.")


def build_inventory(b):
    inv = [
        (b.viz("inv-listeners", "SOC inventory: listening processes and ports", INV_PORTS, "table",
               [a_count("1"), a_terms("2", "process.name", 20), a_terms("3", "source.port", 10),
                a_terms("4", "network.transport", 2)], p_table(), query="interface.state:listening"),
         24, 15),
        (b.viz("inv-ports-agent", "SOC inventory: listeners by agent", INV_PORTS, "table",
               [a_count("1"), a_terms("2", "agent.name", 20)], p_table(),
               query="interface.state:listening"), 24, 15),
        (b.viz("inv-any-bind", "SOC inventory: listeners bound to all interfaces", INV_PORTS, "table",
               [a_count("1"), a_terms("2", "source.port", 20), a_terms("3", "process.name", 3),
                a_terms("4", "agent.name", 5)], p_table(),
               query='interface.state:listening and source.ip:("0.0.0.0" or "::")'), 48, 15),
        (b.viz("inv-pw-status", "SOC inventory: account password status", INV_USERS, "pie",
               [a_count("1"), a_terms("2", "user.password.status", 5)], p_pie()), 16, 15),
        (b.viz("inv-shells", "SOC inventory: user login shells", INV_USERS, "table",
               [a_count("1"), a_terms("2", "user.shell", 12)], p_table()), 16, 15),
        (b.viz("inv-uid0", "SOC inventory: accounts with UID 0", INV_USERS, "table",
               [a_count("1"), a_terms("2", "user.name", 10), a_terms("3", "agent.name", 10)],
               p_table(), query="user.id:0"), 16, 15),
        (b.viz("inv-services", "SOC inventory: active services", INV_SERVICES, "table",
               [a_count("1"), a_terms("2", "service.name", 25)], p_table(),
               query="service.state:(active or running or RUNNING)"), 24, 15),
        (b.viz("inv-packages", "SOC inventory: package count by agent", INV_PACKAGES, "table",
               [a_count("1"), a_terms("2", "agent.name", 25)], p_table()), 24, 15),
    ]
    b.dashboard("inventory", "SOC Overview - Asset Inventory & Attack Surface", inv,
                "Attack surface from the IT-hygiene state indices (Wazuh 4.13+): open listeners, "
                "accounts, shells, running services and package counts.")


# index patterns referenced above: (id == title, time field or None for state indices)
INDEX_PATTERNS = [
    (ALERTS, "timestamp"),
    (MONITORING, "timestamp"),
    (STATS, "timestamp"),
    (VULN, None),
    (INV_PORTS, None),
    (INV_USERS, None),
    (INV_SERVICES, None),
    (INV_PACKAGES, None),
]


def build_index_patterns(b):
    for pattern, time_field in INDEX_PATTERNS:
        attrs = {"title": pattern}
        if time_field:
            attrs["timeFieldName"] = time_field
        b.objects.append({"id": pattern, "type": "index-pattern", "attributes": attrs,
                          "references": []})


def write_ndjson(path, objects):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for obj in objects:
            fh.write(json.dumps(obj, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-dir", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args(argv)
    for fname, fn in (("wazuh_soc_dashboards.ndjson", build_main),
                      ("wazuh_soc_inventory_dashboard.ndjson", build_inventory),
                      ("index_patterns.ndjson", build_index_patterns)):
        b = Builder()
        fn(b)
        write_ndjson(os.path.join(args.out_dir, fname), b.objects)
        kinds = {}
        for o in b.objects:
            kinds[o["type"]] = kinds.get(o["type"], 0) + 1
        print("%s: %d objects (%s)" % (fname, len(b.objects),
                                        ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items()))))


if __name__ == "__main__":
    main()
