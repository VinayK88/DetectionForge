from __future__ import annotations

import json
from pathlib import Path

from detectionforge.replay import evaluate_rule, load_events
from detectionforge.report import build_report
from detectionforge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
rules = load_rules(ROOT / "detections")
events = load_events(ROOT / "data" / "telemetry.jsonl")
runs = [evaluate_rule(rule, events) for rule in rules]
report = build_report(rules, runs)
(ROOT / "reports" / "baseline.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report["summary"], indent=2))
raise SystemExit(0 if all(run.gate_passed for run in runs) else 2)
