#!/usr/bin/env python3
"""Static checks for OpenSearch Dashboards saved-object exports (stdlib only).

  python3 tools/validate_saved_objects.py dashboards/*.ndjson \\
      [--rules-dir DIR ...] [--decoders-dir DIR ...] \\
      [--template INDEX_PATTERN_ID=TEMPLATE.json ...] [--dynamic-prefix data.] \\
      [--no-collide-with OTHER.ndjson ...]

Checks:
  * every line is a JSON object with id / type / attributes / references; (type, id) unique
  * embedded JSON strings (visState, panelsJSON, searchSourceJSON, ...) parse
  * every reference resolves to an object in the given files (index patterns included)
  * every dashboard panelRefName and control indexPatternRefName has a matching reference
  * rule.id / rule.groups / decoder.name values in KQL queries exist in the given rule and
    decoder directories (wildcard values are matched as prefixes)
  * every field used by an aggregation, control or query exists in the index template given
    for its index pattern, or sits under a --dynamic-prefix (keyword via dynamic mapping)
  * no saved-object ID or title collides with the objects in --no-collide-with files
Exit status 1 if any check fails.
"""
import argparse
import glob
import json
import os
import re
import sys

KQL_FIELD_RE = re.compile(r"(?<![\w.@])([A-Za-z@][\w.@-]*)\s*(?::|>=|<=|>|<)")
KQL_KEYWORDS = {"and", "or", "not"}
EMBEDDED = ("visState", "panelsJSON", "optionsJSON", "uiStateJSON")


def flatten_mapping(props, prefix=""):
    out = set()
    for name, spec in props.items():
        if "properties" in spec:
            out |= flatten_mapping(spec["properties"], prefix + name + ".")
        else:
            out.add(prefix + name)
    return out


def template_fields(path):
    with open(path, encoding="utf-8") as fh:
        tpl = json.load(fh)
    mappings = tpl.get("mappings") or tpl.get("template", {}).get("mappings") or {}
    return flatten_mapping(mappings.get("properties", {}))


def rule_catalog(dirs):
    ids, groups = set(), set()
    for d in dirs:
        for path in glob.glob(os.path.join(d, "**", "*.xml"), recursive=True):
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = re.sub(r"<!--.*?-->", "", fh.read(), flags=re.S)
            ids |= set(re.findall(r'<rule\b[^>]*\bid="(\d+)"', text))
            for g in re.findall(r'<group name="([^"]*)"', text) + re.findall(r"<group>([^<]*)</group>", text):
                groups |= {x.strip() for x in g.split(",") if x.strip()}
    return ids, groups


def decoder_catalog(dirs):
    names = set()
    for d in dirs:
        for path in glob.glob(os.path.join(d, "**", "*.xml"), recursive=True):
            with open(path, encoding="utf-8", errors="replace") as fh:
                names |= set(re.findall(r'<decoder name="([^"]+)"', fh.read()))
    return names


def kql_values(query, field):
    """Values a KQL query compares `field` against: field:x, field:"x", field:(a or b)."""
    vals = []
    for m in re.finditer(re.escape(field) + r"\s*:\s*(\([^)]*\)|\"[^\"]*\"|[^\s()]+)", query):
        raw = m.group(1)
        if raw.startswith("("):
            parts = re.split(r"\s+(?:or|and)\s+", raw[1:-1].strip())
        else:
            parts = [raw]
        vals.extend(p.strip().strip('"') for p in parts if p.strip())
    return vals


def kql_fields(query):
    stripped = re.sub(r'"[^"]*"', '""', query)
    return {f for f in KQL_FIELD_RE.findall(stripped) if f not in KQL_KEYWORDS}


def value_known(value, known):
    if value.endswith("*"):
        return any(k.startswith(value[:-1]) for k in known)
    return value in known


def load_objects(paths, errors):
    objs = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    errors.append("%s:%d: blank line" % (path, n))
                    continue
                try:
                    obj = json.loads(line)
                except ValueError as exc:
                    errors.append("%s:%d: invalid JSON (%s)" % (path, n, exc))
                    continue
                if not isinstance(obj, dict) or not all(k in obj for k in ("id", "type", "attributes")):
                    errors.append("%s:%d: missing id/type/attributes" % (path, n))
                    continue
                obj.setdefault("references", [])
                obj["_src"] = "%s:%d" % (os.path.basename(path), n)
                objs.append(obj)
    return objs


def check(args):
    errors, notes = [], []
    objs = load_objects(args.files, errors)
    by_key = {}
    for o in objs:
        key = (o["type"], o["id"])
        if key in by_key:
            errors.append("%s: duplicate %s/%s" % (o["_src"], o["type"], o["id"]))
        by_key[key] = o

    rule_ids, rule_groups = rule_catalog(args.rules_dir) if args.rules_dir else (None, None)
    decoders = decoder_catalog(args.decoders_dir) if args.decoders_dir else None
    fields = {}
    for spec in args.template:
        pattern, path = spec.split("=", 1)
        fields[pattern] = fields.get(pattern, set()) | template_fields(path)
    used = {"rule.id": set(), "rule.groups": set(), "decoder.name": set(), "fields": 0}

    def check_query(src, query, idx):
        if rule_ids is not None:
            for v in kql_values(query, "rule.id"):
                used["rule.id"].add(v)
                if not value_known(v, rule_ids):
                    errors.append("%s: rule.id %s not found in rules dirs" % (src, v))
            for v in kql_values(query, "rule.groups"):
                used["rule.groups"].add(v)
                if not value_known(v, rule_groups):
                    errors.append("%s: rule.groups %s not found in rules dirs" % (src, v))
        if decoders is not None:
            for v in kql_values(query, "decoder.name"):
                used["decoder.name"].add(v)
                if not value_known(v, decoders):
                    errors.append("%s: decoder.name %s not found in decoders dirs" % (src, v))
        for f in kql_fields(query):
            check_field(src, f, idx)

    def check_field(src, field, idx):
        if idx not in fields:
            return
        used["fields"] += 1
        if field in fields[idx]:
            return
        if any(field.startswith(p) for p in args.dynamic_prefix):
            notes.append("%s: %s is dynamic-mapped (not in the %s template)" % (src, field, idx))
            return
        errors.append("%s: field %s not in the template for %s" % (src, field, idx))

    for o in objs:
        src = "%s %s/%s" % (o["_src"], o["type"], o["id"])
        attrs = o["attributes"]
        parsed = {}
        for k in EMBEDDED:
            if k in attrs:
                try:
                    parsed[k] = json.loads(attrs[k])
                except ValueError as exc:
                    errors.append("%s: %s does not parse (%s)" % (src, k, exc))
        ss = {}
        meta = attrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON")
        if meta is not None:
            try:
                ss = json.loads(meta)
            except ValueError as exc:
                errors.append("%s: searchSourceJSON does not parse (%s)" % (src, exc))
        refs = {r.get("name"): r for r in o["references"]}
        for r in o["references"]:
            if (r.get("type"), r.get("id")) not in by_key:
                errors.append("%s: reference %s -> %s/%s not in the given files"
                              % (src, r.get("name"), r.get("type"), r.get("id")))
        idx = None
        if ss.get("indexRefName"):
            ref = refs.get(ss["indexRefName"])
            if not ref:
                errors.append("%s: indexRefName %s has no reference" % (src, ss["indexRefName"]))
            else:
                idx = ref["id"]
        if o["type"] == "dashboard":
            for p in parsed.get("panelsJSON", []):
                if p.get("panelRefName") not in refs:
                    errors.append("%s: panel %s has no reference" % (src, p.get("panelRefName")))
        vis = parsed.get("visState")
        if vis:
            if vis.get("type") == "input_control_vis":
                for c in vis.get("params", {}).get("controls", []):
                    ref = refs.get(c.get("indexPatternRefName"))
                    if not ref:
                        errors.append("%s: control %s has no reference" % (src, c.get("id")))
                    else:
                        check_field(src, c.get("fieldName"), ref["id"])
            for agg in vis.get("aggs", []):
                f = agg.get("params", {}).get("field")
                if f:
                    check_field(src, f, idx)
                for flt in agg.get("params", {}).get("filters", []):
                    check_query(src, flt.get("input", {}).get("query", ""), idx)
        q = ss.get("query", {}).get("query", "")
        if q:
            check_query(src, q, idx)

    for other in args.no_collide_with:
        for o in load_objects([other], errors):
            for mine in objs:
                if mine["id"] == o["id"]:
                    errors.append("%s: id %s collides with %s" % (mine["_src"], o["id"], o["_src"]))
                t1, t2 = mine["attributes"].get("title"), o["attributes"].get("title")
                if t1 and t1 == t2:
                    errors.append("%s: title %r collides with %s" % (mine["_src"], t1, o["_src"]))

    kinds = {}
    for o in objs:
        kinds[o["type"]] = kinds.get(o["type"], 0) + 1
    print("objects: %s" % ", ".join("%d %s" % (n, k) for k, n in sorted(kinds.items())))
    if rule_ids is not None:
        print("rule.id values checked: %d (%s)" % (len(used["rule.id"]), " ".join(sorted(used["rule.id"]))))
        print("rule.groups values checked: %d (%s)" % (len(used["rule.groups"]),
                                                       " ".join(sorted(used["rule.groups"]))))
    if decoders is not None:
        print("decoder.name values checked: %s" % " ".join(sorted(used["decoder.name"])))
    print("field references checked against templates: %d" % used["fields"])
    for n in sorted(set(notes)):
        print("note: " + n)
    for e in errors:
        print("ERROR: " + e)
    print("RESULT: %s (%d errors)" % ("FAIL" if errors else "OK", len(errors)))
    return 1 if errors else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static checks for saved-object NDJSON exports.")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--rules-dir", action="append", default=[])
    ap.add_argument("--decoders-dir", action="append", default=[])
    ap.add_argument("--template", action="append", default=[], metavar="PATTERN_ID=FILE")
    ap.add_argument("--dynamic-prefix", action="append", default=[])
    ap.add_argument("--no-collide-with", action="append", default=[])
    return check(ap.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
