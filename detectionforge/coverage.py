from __future__ import annotations

from collections import defaultdict

from .models import DetectionRule


def attack_coverage(rules: list[DetectionRule]) -> dict[str, list[str]]:
    coverage: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        for technique in rule.attack_techniques:
            coverage[technique].append(rule.id)
    return {technique: sorted(rule_ids) for technique, rule_ids in sorted(coverage.items())}
