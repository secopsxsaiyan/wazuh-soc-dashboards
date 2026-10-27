# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-26

- Initial public release.
- Nine SOC overview dashboards on the stock Wazuh index patterns: Triage Cockpit,
  Authentication (Linux & Windows hosts), File Integrity Monitoring, Vulnerability Detection,
  Configuration Assessment & Rootcheck, Threat Detection (cross-pack), MISP IOC Matches, Wazuh
  Pipeline Health, Agent Health. Agent and rule-level filter controls; no hard-coded agents.
- Asset Inventory & Attack Surface dashboard for the Wazuh 4.13+ IT-hygiene state indices
  (separate file).
- `index_patterns.ndjson` for installs missing one of the referenced index patterns.
- No overlap with the UniFi, Proxmox VE, TrueNAS and Nginx Proxy Manager pack dashboards: their events are
  excluded from cross-source panels, all IDs use the `socov-` prefix.
- ATT&CK Navigator layer (format 4.5, ATT&CK v20) built from the eight public packs' rule XML,
  plus a variant that includes the stock Wazuh 4.14 ruleset. Revoked technique IDs are mapped to
  their replacements.
- `tools/validate_saved_objects.py` static checks and unit tests.
