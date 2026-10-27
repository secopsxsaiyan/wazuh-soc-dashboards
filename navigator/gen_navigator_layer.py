#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer (layer format 4.5) from Wazuh rule XML <mitre> tags (stdlib only).

Every ATT&CK technique referenced by an alerting rule (level >= 1) becomes a scored cell:

  score    highest rule level that detects the technique (1-15)
  color    band of that level: 12+ critical, 10-11 triage gate, 7-9 indexed below the gate,
           1-6 informational
  comment  contributing rule IDs with level and pack, e.g. "wazuh-truenas: 100365 (L10)"
  metadata rule count and pack list

Inputs are the public pack repositories (their custom_rules/*.xml); optionally the stock Wazuh
ruleset is added as a separate source (--stock-rules), labelled "wazuh-stock".

Output is deterministic: techniques sorted by ID, rule lists sorted, no timestamps.

Examples:
  # layer from the packs cloned side by side in ./packs/wazuh-*
  python3 gen_navigator_layer.py --packs-dir ./packs -o navigator-layer.json
  # same, plus the stock ruleset copied out of a manager
  python3 gen_navigator_layer.py --packs-dir ./packs \\
      --stock-rules /var/ossec/ruleset/rules -o navigator-layer-with-stock.json
  # optional: map revoked IDs to their replacements using an ATT&CK STIX bundle (recommended)
  python3 gen_navigator_layer.py --packs-dir ./packs --attack-bundle enterprise-attack-20.0.json
"""
import argparse
import glob
import json
import os
import re
import sys

ATTACK_VERSION = "20"
NAVIGATOR_VERSION = "5.3.2"
LAYER_VERSION = "4.5"
STOCK_SOURCE = "wazuh-stock"
REPO = "https://github.com/secopsxsaiyan"

# (min level, color, legend label) - first match wins
BANDS = [
    (12, "#1a9850", "L12+ critical detection"),
    (10, "#66bd63", "L10-11 at the triage gate"),
    (7, "#a6d96a", "L7-9 indexed, below the gate"),
    (1, "#d9ef8b", "L1-6 informational"),
]

_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_RULE_RE = re.compile(r"<rule\b([^>]*)>(.*?)</rule>", re.S)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')
_MITRE_BLOCK_RE = re.compile(r"<mitre>(.*?)</mitre>", re.S)
_TID_RE = re.compile(r"<id>\s*(T\d{4}(?:\.\d{3})?)\s*</id>", re.I)
_PACK_NAME_RE = re.compile(r"(wazuh-[a-z0-9-]+)$")


def parse_rules(text):
    """Yield (rule_id, level, [technique IDs]) for every rule in a Wazuh rules file.

    Regex-based on purpose: rule files are XML fragments with several top-level <group>
    elements, and some stock files contain characters a strict XML parser rejects."""
    text = _COMMENT_RE.sub("", text)
    for m in _RULE_RE.finditer(text):
        attrs = dict(_ATTR_RE.findall(m.group(1)))
        if "id" not in attrs or "level" not in attrs:
            continue
        tids = []
        for block in _MITRE_BLOCK_RE.findall(m.group(2)):
            tids.extend(t.upper() for t in _TID_RE.findall(block))
        yield attrs["id"], int(attrs["level"]), sorted(set(tids))


def pack_name(path):
    """Pack name from a checkout directory name: '.../wazuh-unifi' -> 'wazuh-unifi'."""
    base = os.path.basename(os.path.normpath(path))
    m = _PACK_NAME_RE.search(base)
    return m.group(1) if m else base


def collect(sources):
    """sources: list of (source_name, [xml paths]). Returns {tid: [(source, rule_id, level)]}."""
    cov = {}
    for source, paths in sources:
        for path in sorted(paths):
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for rid, level, tids in parse_rules(text):
                if level < 1:          # level 0 rules suppress; they never alert
                    continue
                for tid in tids:
                    cov.setdefault(tid, []).append((source, rid, level))
    for tid in cov:
        cov[tid] = sorted(set(cov[tid]), key=lambda r: (r[0], int(r[1]) if r[1].isdigit() else 0, r[1]))
    return cov


def band(level):
    for floor, color, _label in BANDS:
        if level >= floor:
            return color
    return BANDS[-1][1]


def technique_entry(tid, rules, tagged_as=None):
    top = max(level for _s, _r, level in rules)
    by_source = {}
    for source, rid, level in rules:
        by_source.setdefault(source, []).append("%s (L%d)" % (rid, level))
    comment = "; ".join("%s: %s" % (s, ", ".join(by_source[s])) for s in sorted(by_source))
    if tagged_as:
        comment += " [rules tag %s, revoked in this ATT&CK version]" % ", ".join(sorted(tagged_as))
    return {
        "techniqueID": tid,
        "score": top,
        "color": band(top),
        "comment": comment,
        "enabled": True,
        "metadata": [{"name": "rules", "value": str(len(rules))},
                     {"name": "sources", "value": ", ".join(sorted(by_source))}],
        "showSubtechniques": False,
    }


def build_layer(cov, name, description, renamed=None):
    renamed = renamed or {}
    techniques = [technique_entry(tid, cov[tid], renamed.get(tid)) for tid in sorted(cov)]
    # Expand parents of annotated sub-techniques so the coloured cells are visible on load.
    scored = {t["techniqueID"] for t in techniques}
    parents = sorted({tid.split(".")[0] for tid in scored if "." in tid})
    for parent in parents:
        if parent in scored:
            next(t for t in techniques if t["techniqueID"] == parent)["showSubtechniques"] = True
        else:
            techniques.append({"techniqueID": parent, "enabled": True, "comment": "",
                               "metadata": [], "showSubtechniques": True})
    techniques.sort(key=lambda t: t["techniqueID"])
    sources = sorted({s for rules in cov.values() for s, _r, _l in rules})
    links = [{"label": s, "url": "%s/%s" % (REPO, s)} for s in sources if s != STOCK_SOURCE]
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": True, "countUnscored": False,
                   "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#1a9850"], "minValue": 0, "maxValue": 15},
        "legendItems": [{"label": label, "color": color} for _f, color, label in BANDS],
        "metadata": [{"name": "sources", "value": ", ".join(sources)},
                     {"name": "techniques", "value": str(len(cov))}],
        "links": links,
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def load_attack(bundle_path):
    """Read an ATT&CK STIX bundle. Returns ({tid: status}, {revoked tid: replacement tid});
    status is "ok", "revoked" or "deprecated"."""
    with open(bundle_path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    ext_id, status = {}, {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                ext_id[obj["id"]] = ref["external_id"]
                st = "revoked" if obj.get("revoked") else (
                    "deprecated" if obj.get("x_mitre_deprecated") else "ok")
                if status.get(ref["external_id"]) != "ok":
                    status[ref["external_id"]] = st
    replaced = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            src, dst = ext_id.get(obj.get("source_ref")), ext_id.get(obj.get("target_ref"))
            if src and dst:
                replaced[src] = dst
    return status, replaced


def apply_attack(cov, status, replaced):
    """Map revoked technique IDs to their replacement (following chains). Returns
    (new coverage, {replacement: [original ids]}, [problems])."""
    out, renamed, problems = {}, {}, []
    for tid in sorted(cov):
        cur, seen = tid, set()
        while status.get(cur) == "revoked" and cur in replaced and cur not in seen:
            seen.add(cur)
            cur = replaced[cur]
        st = status.get(cur)
        if st is None:
            problems.append("%s: not in the ATT&CK bundle" % tid)
            continue
        if st != "ok":
            problems.append("%s: %s with no replacement" % (tid, st))
            continue
        if cur != tid:
            renamed.setdefault(cur, []).append(tid)
        out.setdefault(cur, []).extend(cov[tid])
    for tid in out:
        out[tid] = sorted(set(out[tid]), key=lambda r: (r[0], int(r[1]) if r[1].isdigit() else 0, r[1]))
    return out, renamed, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build an ATT&CK Navigator layer from Wazuh rule XML.")
    ap.add_argument("--packs-dir", required=True,
                    help="directory holding the pack checkouts (each with custom_rules/*.xml)")
    ap.add_argument("--stock-rules", help="optional: stock Wazuh ruleset dir (/var/ossec/ruleset/rules)")
    ap.add_argument("--attack-bundle",
                    help="optional: ATT&CK enterprise STIX bundle; revoked IDs are mapped to their "
                         "replacement, unknown/deprecated IDs fail the run")
    ap.add_argument("-o", "--output", default="navigator-layer.json")
    args = ap.parse_args(argv)

    sources = []
    for pack_dir in sorted(glob.glob(os.path.join(args.packs_dir, "*"))):
        paths = glob.glob(os.path.join(pack_dir, "custom_rules", "*.xml"))
        if paths:
            sources.append((pack_name(pack_dir), paths))
    if not sources:
        ap.error("no */custom_rules/*.xml under %s" % args.packs_dir)
    name = "Wazuh detection packs - ATT&CK coverage"
    desc = ("Techniques tagged in the <mitre> blocks of alerting rules (level >= 1) in: %s. "
            "Score = highest rule level for the technique." % ", ".join(s for s, _p in sources))
    if args.stock_rules:
        stock = glob.glob(os.path.join(args.stock_rules, "*.xml"))
        if not stock:
            ap.error("no *.xml under %s" % args.stock_rules)
        sources.append((STOCK_SOURCE, stock))
        name = "Wazuh detection packs + stock ruleset - ATT&CK coverage"
        desc += " Includes the stock Wazuh ruleset as source '%s'." % STOCK_SOURCE

    cov = collect(sources)
    renamed = {}
    if args.attack_bundle:
        cov, renamed, problems = apply_attack(cov, *load_attack(args.attack_bundle))
        if problems:
            print("ATT&CK check failed:\n  " + "\n  ".join(problems), file=sys.stderr)
            return 1
        for new_id in sorted(renamed):
            print("  remapped %s -> %s" % (", ".join(renamed[new_id]), new_id))
    layer = build_layer(cov, name, desc, renamed)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(layer, fh, indent=2, sort_keys=False, ensure_ascii=False)
        fh.write("\n")
    rules = {(s, r) for v in cov.values() for s, r, _l in v}
    print("wrote %s: %d techniques from %d rules (%s)"
          % (args.output, len(cov), len(rules), ", ".join(s for s, _p in sources)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
