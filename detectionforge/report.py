from __future__ import annotations

from dataclasses import asdict

from .coverage import attack_coverage
from .models import DetectionRule, RuleRun


def build_report(rules: list[DetectionRule], runs: list[RuleRun]) -> dict:
    return {
        "summary": {
            "rules": len(rules),
            "passing": sum(run.gate_passed for run in runs),
            "failing": sum(not run.gate_passed for run in runs),
            "attack_techniques": len(attack_coverage(rules)),
        },
        "rules": [asdict(run) for run in runs],
        "attack_coverage": attack_coverage(rules),
    }
