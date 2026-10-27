#!/usr/bin/env python3
"""Unit tests for the generators and the validator (stdlib unittest, no network, no Wazuh).

    python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("dashboards", "navigator", "tools"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import gen_navigator_layer as nav          # noqa: E402
import gen_soc_dashboards as dash          # noqa: E402
import validate_saved_objects as val       # noqa: E402

RULES_XML = """<!-- <rule id="999999" level="15"><mitre><id>T9999</id></mitre></rule> -->
<group name="test,">
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <description>x</description>
    <mitre><id>T1110.001</id><id>T1078</id></mitre>
  </rule>
  <rule level="12" id="100002" frequency="5" timeframe="60">
    <if_matched_sid>100001</if_matched_sid>
    <mitre>
      <id>t1110.001</id>
    </mitre>
  </rule>
  <rule id="100003" level="0">
    <mitre><id>T1046</id></mitre>
  </rule>
  <rule id="100004" level="3"><description>no mitre</description></rule>
</group>
"""


class NavigatorTests(unittest.TestCase):
    def test_parse_rules_attr_order_comments_case(self):
        got = list(nav.parse_rules(RULES_XML))
        self.assertEqual(got[0], ("100001", 10, ["T1078", "T1110.001"]))
        self.assertEqual(got[1], ("100002", 12, ["T1110.001"]))
        self.assertNotIn("999999", [r[0] for r in got])          # commented-out rule ignored

    def _cov(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.xml")
            with open(path, "w") as fh:
                fh.write(RULES_XML)
            return nav.collect([("wazuh-test", [path])])

    def test_collect_skips_level0(self):
        cov = self._cov()
        self.assertNotIn("T1046", cov)
        self.assertEqual(cov["T1110.001"], [("wazuh-test", "100001", 10), ("wazuh-test", "100002", 12)])

    def test_layer_shape_and_determinism(self):
        cov = self._cov()
        a = nav.build_layer(cov, "n", "d")
        b = nav.build_layer(cov, "n", "d")
        self.assertEqual(json.dumps(a), json.dumps(b))
        self.assertEqual(a["versions"]["layer"], "4.5")
        self.assertEqual(a["domain"], "enterprise-attack")
        ids = [t["techniqueID"] for t in a["techniques"]]
        self.assertEqual(ids, sorted(ids))
        sub = next(t for t in a["techniques"] if t["techniqueID"] == "T1110.001")
        self.assertEqual(sub["score"], 12)
        self.assertEqual(sub["color"], nav.BANDS[0][1])
        self.assertIn("100001 (L10)", sub["comment"])
        self.assertIn("wazuh-test", sub["comment"])
        parent = next(t for t in a["techniques"] if t["techniqueID"] == "T1110")
        self.assertTrue(parent["showSubtechniques"])
        self.assertNotIn("score", parent)

    def test_bands(self):
        self.assertEqual(nav.band(15), "#1a9850")
        self.assertEqual(nav.band(10), "#66bd63")
        self.assertEqual(nav.band(7), "#a6d96a")
        self.assertEqual(nav.band(1), "#d9ef8b")

    def test_pack_name(self):
        self.assertEqual(nav.pack_name("/x/wazuh-unifi"), "wazuh-unifi")
        self.assertEqual(nav.pack_name("/x/public-wazuh-unifi/"), "wazuh-unifi")

    def test_apply_attack_remaps_revoked_and_flags_unknown(self):
        cov = {"T1562.001": [("p", "1", 10)], "T1685": [("p", "2", 12)], "T0000": [("p", "3", 3)]}
        status = {"T1562.001": "revoked", "T1685": "ok"}
        out, renamed, problems = nav.apply_attack(cov, status, {"T1562.001": "T1685"})
        self.assertEqual(out["T1685"], [("p", "1", 10), ("p", "2", 12)])
        self.assertEqual(renamed, {"T1685": ["T1562.001"]})
        self.assertEqual(problems, ["T0000: not in the ATT&CK bundle"])


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        dash.main(["--out-dir", self.tmp.name])

    def tearDown(self):
        self.tmp.cleanup()

    def _load(self, name):
        with open(os.path.join(self.tmp.name, name)) as fh:
            return [json.loads(line) for line in fh]

    def test_ids_prefixed_and_unique(self):
        objs = self._load("wazuh_soc_dashboards.ndjson") + self._load("wazuh_soc_inventory_dashboard.ndjson")
        ids = [o["id"] for o in objs]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(i.startswith(dash.PFX) for i in ids))

    def test_tables_use_bucket_schema(self):
        for o in self._load("wazuh_soc_dashboards.ndjson"):
            if o["type"] != "visualization":
                continue
            vis = json.loads(o["attributes"]["visState"])
            if vis["type"] == "table":
                for agg in vis["aggs"]:
                    if agg["type"] != "count" and agg["schema"] != "metric":
                        self.assertEqual(agg["schema"], "bucket", o["id"])

    def test_no_product_pack_panels(self):
        # product packs ship their own dashboards: no query may target their rule groups
        # except the exclusion clause and the single pack-count row
        for o in self._load("wazuh_soc_dashboards.ndjson"):
            if o["id"] == dash.PFX + "triage-packs" or o["type"] != "visualization":
                continue
            q = json.loads(o["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])["query"]["query"]
            q = q.replace(dash.PRODUCT_PACKS_EXCLUDE, "").replace("not decoder.name:unifi*", "")
            for word in ("unifi", "proxmox", "truenas"):
                self.assertNotIn(word, q, o["id"])

    def test_validator_passes_generated_files(self):
        files = [os.path.join(self.tmp.name, f) for f in
                 ("wazuh_soc_dashboards.ndjson", "wazuh_soc_inventory_dashboard.ndjson",
                  "index_patterns.ndjson")]
        self.assertEqual(val.main(files), 0)

    def test_validator_catches_dangling_reference(self):
        files = [os.path.join(self.tmp.name, "wazuh_soc_dashboards.ndjson")]   # no index patterns
        self.assertEqual(val.main(files), 1)


class ValidatorTests(unittest.TestCase):
    def test_kql_values(self):
        q = 'rule.id:(100001 or 100002) and not rule.groups:"a b" and decoder.name:unifi*'
        self.assertEqual(val.kql_values(q, "rule.id"), ["100001", "100002"])
        self.assertEqual(val.kql_values(q, "rule.groups"), ["a b"])
        self.assertEqual(val.kql_values(q, "decoder.name"), ["unifi*"])

    def test_kql_fields_ignores_quoted_text(self):
        q = 'source.ip:("0.0.0.0" or "::") and rule.level >= 10 and data.x:"a:b"'
        self.assertEqual(val.kql_fields(q), {"source.ip", "rule.level", "data.x"})

    def test_value_known_wildcard(self):
        self.assertTrue(val.value_known("unifi*", {"unifi-cef"}))
        self.assertFalse(val.value_known("npm*", {"unifi-cef"}))


if __name__ == "__main__":
    unittest.main()
