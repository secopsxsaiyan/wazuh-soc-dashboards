# Wazuh SOC overview dashboards & ATT&CK Navigator coverage layer

Fleet-level **SOC dashboards** for any Wazuh 4.x install (Wazuh dashboard / OpenSearch
Dashboards 2.x), plus an **ATT&CK Navigator layer** that maps the detection coverage of the
public Wazuh rule packs below.

> No rules, decoders or agents here. The dashboards are saved-object exports built by a
> stdlib-only generator; the layer is built from the packs' rule XML.

**Companion packs** (rules + product dashboards):
[wazuh-unifi](https://github.com/secopsxsaiyan/wazuh-unifi) ·
[wazuh-proxmox](https://github.com/secopsxsaiyan/wazuh-proxmox) ·
[wazuh-truenas](https://github.com/secopsxsaiyan/wazuh-truenas) ·
[wazuh-nginx-proxy-manager](https://github.com/secopsxsaiyan/wazuh-nginx-proxy-manager) ·
[wazuh-threat-detection](https://github.com/secopsxsaiyan/wazuh-threat-detection) ·
[wazuh-fim-escalation](https://github.com/secopsxsaiyan/wazuh-fim-escalation) ·
[wazuh-windows](https://github.com/secopsxsaiyan/wazuh-windows) ·
[wazuh-misp-ioc](https://github.com/secopsxsaiyan/wazuh-misp-ioc)

## Contents

```
dashboards/
  gen_soc_dashboards.py                  # generator (stdlib only)
  wazuh_soc_dashboards.ndjson            # 9 dashboards on the stock Wazuh index patterns (import this)
  wazuh_soc_inventory_dashboard.ndjson   # asset-inventory dashboard (Wazuh 4.13+ IT-hygiene indices)
  index_patterns.ndjson                  # the index patterns the dashboards reference (only if missing)
navigator/
  gen_navigator_layer.py                 # layer generator (stdlib only)
  navigator-layer.json                   # coverage of the 8 public packs
  navigator-layer-with-stock.json        # same + the stock Wazuh 4.14 ruleset
tools/
  validate_saved_objects.py              # static checks for the ndjson exports
tests/
  test_generators.py                     # unit tests (python3 -m unittest discover -s tests)
```

## What does not overlap with the pack dashboards

The UniFi, Proxmox VE, TrueNAS and Nginx Proxy Manager packs each ship their own dashboard
(`UniFi Threats`, `Proxmox VE Security & Threats`, `TrueNAS Audit & Threats`,
`Nginx Proxy Manager - Web Threats`). This repo charts none of their
product-specific signal again:

- Cross-source panels (authentication) exclude those packs' events with
  `not rule.groups:(unifi or proxmox or truenas or npm_access or npm_error or npm_cert)`.
- The MISP IOC dashboard excludes UniFi-decoded events (`not decoder.name:unifi*`), which the UniFi
  dashboard already charts.
- The only cross-product element is one row on the Triage Cockpit: alert counts per pack and
  links to the three pack dashboards.
- All saved-object IDs start with `socov-` and all titles with `SOC`, so importing this repo
  next to the pack dashboards never overwrites anything.

## Dashboards

All alert dashboards (except Vulnerability, Pipeline, Agent Health and Inventory, which use
state/statistics indices) start with a filter row: an **Agent** picker and a **Rule level**
range, populated from your data. No agent names are hard-coded.

| Dashboard | Index pattern | Panels |
|-----------|---------------|--------|
| **SOC Overview - Triage Cockpit** | `wazuh-alerts-*` | alerts over time by level; L10+ (triage gate) and L12+ counts; L10+ alerts by rule and agent; top rules; alerts by agent; MITRE tactics, technique IDs and techniques by tactic; alerts per detection pack; links to the pack dashboards |
| **SOC Overview - Authentication (Linux & Windows hosts)** | `wazuh-alerts-*` | auth events over time (success / failed / repeated failures / sudo); failure count; failure source IPs with country; Linux target accounts; Windows logons by target account and event ID; sudo by agent and user; brute-force alerts |
| **SOC Overview - File Integrity Monitoring** | `wazuh-alerts-*` | changes over time by event; most-changed paths; changes by agent; changes by owning user; sensitive-path escalations from wazuh-fim-escalation and the wazuh-threat-detection `/boot` rule (count, table, by MITRE technique) |
| **SOC Overview - Vulnerability Detection** | `wazuh-states-vulnerabilities-*` | findings by severity; Critical and High counts; findings by agent; top packages by max CVSS (with affected-agent count); top Critical/High CVEs; unscored findings; findings by detection date |
| **SOC Overview - Configuration Assessment & Rootcheck** | `wazuh-alerts-*` | SCA results; results by policy; failed checks by agent; top failing checks; lowest score by policy and agent; rootcheck anomalies over time and by title |
| **SOC Overview - Threat Detection (cross-pack)** | `wazuh-alerts-*` | wazuh-threat-detection: L12+ detection count, detections over time, auditd execve (reverse shell, audit tamper, miner), Suricata IDS, Spamhaus DROP ranges, agent enrollment, clock change / rapid sudo; wazuh-windows: VPN-client service, WSL |
| **SOC Overview - MISP IOC Matches** | `wazuh-alerts-*` | wazuh-misp-ioc matches from all non-UniFi sources: count, by indicator type (IP / file / URL / domain / JA3), by agent and decoder, IP, file and URL tables, over time |
| **SOC Overview - Wazuh Pipeline Health** | `wazuh-statistics-*` | events received vs alerts written; dropped events; alert and event queue usage |
| **SOC Overview - Agent Health** | `wazuh-monitoring-*` | active and disconnected agents; status distribution; agents by status; status over time |
| **SOC Overview - Asset Inventory & Attack Surface** *(separate file)* | `wazuh-states-inventory-{ports,users,services,packages}-*` | listening processes and ports; listeners by agent; listeners bound to all interfaces; password status; login shells; UID 0 accounts; active services; package count by agent |

Panels for packs you do not run stay empty; everything else works on a stock install.

## Requirements

- **Wazuh 4.x** manager + indexer + dashboard (tested by import into OpenSearch Dashboards
  2.19; panel schema 2.16). The inventory dashboard needs the IT-hygiene state indices from
  **Wazuh 4.13+**; the vulnerability dashboard needs the 4.8+ vulnerability-detector state index.
- The index patterns `wazuh-alerts-*`, `wazuh-monitoring-*`, `wazuh-statistics-*`,
  `wazuh-states-vulnerabilities-*` (and for the inventory dashboard
  `wazuh-states-inventory-ports-*`, `-users-*`, `-services-*`, `-packages-*`). The Wazuh dashboard
  creates them with **ID = title**, which is what these exports reference. If one is missing
  (plain OpenSearch Dashboards, statistics job disabled), import it from `index_patterns.ndjson`.
- Optional: the companion packs above, for the threat-detection, FIM-escalation, Windows and
  MISP panels.

## Import

Wazuh dashboard -> **Dashboards Management -> Saved objects -> Import** -> select
`dashboards/wazuh_soc_dashboards.ndjson` (and `wazuh_soc_inventory_dashboard.ndjson` on 4.13+).
Or via the API:

```bash
curl -k -u <DASHBOARD USER>:<DASHBOARD PASS> -X POST \
  "https://<WAZUH DASHBOARD>/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" --form file=@dashboards/wazuh_soc_dashboards.ndjson
```

If the import reports `missing_references` for an index pattern, import only that pattern from
`index_patterns.ndjson` (**without** overwrite: do not replace the patterns the Wazuh dashboard
created), then import the dashboards again.

Some panels aggregate fields that the Wazuh alerts template maps dynamically
(`data.win.*`, Suricata `data.alert.*` / `data.src_ip` / `data.dest_ip`). They appear in the
`wazuh-alerts-*` field list once such an event has been indexed; if a panel says a field is
missing, refresh the index pattern's field list.

## Regenerate the dashboards

```bash
cd dashboards
python3 gen_soc_dashboards.py          # writes the three .ndjson files next to the script
```

Queries, rule IDs and panel layouts are constants at the top of the generator. Validate after
editing:

```bash
python3 tools/validate_saved_objects.py dashboards/*.ndjson \
  --rules-dir /var/ossec/ruleset/rules --rules-dir /var/ossec/etc/rules \
  --decoders-dir /var/ossec/ruleset/decoders --decoders-dir /var/ossec/etc/decoders \
  --template "wazuh-alerts-*=<path to wazuh-template.json>" --dynamic-prefix data. \
  --no-collide-with <pack>/dashboards/<pack dashboard>.ndjson
```

It checks that every line is valid JSON, every reference resolves within the given files,
rule IDs / groups / decoder names in queries exist, aggregated fields exist in the given index
templates, and no ID or title collides with the pack dashboards.

## ATT&CK Navigator layer

`navigator/navigator-layer.json` (layer format **4.5**, ATT&CK **v20**, enterprise domain) has
one cell per technique tagged in an alerting rule (level >= 1) of the eight packs:

- **score** = highest rule level that detects the technique; **color** by band:
  L12+ critical, L10-11 at the triage gate, L7-9 indexed below the gate, L1-6 informational
  (legend included);
- **comment** = contributing rules per pack, e.g. `wazuh-truenas: 100365 (L10)`;
- **metadata** = rule count and packs; parents of tagged sub-techniques are expanded.

`navigator-layer-with-stock.json` adds the stock Wazuh 4.14 ruleset as source `wazuh-stock`.

Where a pack still tags a technique that ATT&CK v20 revoked (for example `T1562.001` -> `T1685`),
the layer uses the replacement ID and the comment notes the original tag.

### View it

1. Open <https://mitre-attack.github.io/attack-navigator/>.
2. **Open Existing Layer -> Upload from local** and pick `navigator-layer.json`, or
   **Load from URL** with the raw GitHub URL
   `https://raw.githubusercontent.com/secopsxsaiyan/wazuh-soc-dashboards/main/navigator/navigator-layer.json`.
3. Hover a cell for the contributing rules; sort by score to see the strongest coverage first.

### Regenerate it

Clone the packs side by side, then:

```bash
mkdir packs && cd packs
for p in unifi proxmox truenas threat-detection fim-escalation windows misp-ioc; do
  git clone --depth 1 https://github.com/secopsxsaiyan/wazuh-$p
done
cd ..
# ATT&CK bundle used to map revoked IDs (recommended)
curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json

python3 navigator/gen_navigator_layer.py --packs-dir packs \
  --attack-bundle enterprise-attack-20.0.json -o navigator/navigator-layer.json
# optional: add the stock ruleset (copy /var/ossec/ruleset/rules out of a manager first)
python3 navigator/gen_navigator_layer.py --packs-dir packs --stock-rules ./stock-rules \
  --attack-bundle enterprise-attack-20.0.json -o navigator/navigator-layer-with-stock.json
```

Output is deterministic (sorted, no timestamps), so a diff shows exactly what changed in
coverage. Without `--attack-bundle` the IDs are written exactly as tagged.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Disclaimer

Provided as-is, with no warranty. Panel queries assume the stock Wazuh field names and the
companion packs' rule IDs; review them against your own deployment.

## License

MIT - see [LICENSE](LICENSE).
