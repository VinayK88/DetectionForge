# Architecture

DetectionForge separates authoring, compilation, evaluation, and deployment policy so a query cannot be treated as production-ready merely because it parses.

1. **Rule authoring** — Sigma-style YAML with IDs, log source, selectors, ATT&CK tags, and documented false positives.
2. **Validation** — required fields, unique IDs, supported condition grammar, and supported field modifiers.
3. **Backend compilation** — a deliberately bounded KQL compiler for the supported rule subset.
4. **Replay evaluation** — the same rule logic is applied to versioned malicious and benign telemetry.
5. **Quality gate** — precision, recall, and false-positive-rate thresholds must pass before merge.
6. **Coverage** — ATT&CK mappings are aggregated across the rule set.
7. **Feedback** — analyst dispositions are summarized separately from synthetic benchmark labels.
8. **Deployment boundary** — this public project stops before automatic SIEM deployment; production rollout should require approval, staged/shadow deployment, monitoring, and rollback.

The compiler is intentionally not a full Sigma implementation. Production integrations should delegate broad Sigma compatibility to maintained upstream tooling and keep DetectionForge focused on regression methodology and operational quality gates.
