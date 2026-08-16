from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import DetectionRule


REQUIRED_FIELDS = {"id", "title", "status", "logsource", "detection", "level"}


def load_rule(path: str | Path) -> DetectionRule:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected YAML object")
    missing = sorted(REQUIRED_FIELDS - raw.keys())
    if missing:
        raise ValueError(f"{path}: missing required fields: {', '.join(missing)}")
    detection = raw["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError(f"{path}: detection.condition is required")
    selectors = [k for k in detection if k != "condition"]
    if not selectors:
        raise ValueError(f"{path}: at least one selector is required")
    return DetectionRule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        status=str(raw["status"]),
        logsource=dict(raw["logsource"]),
        detection=detection,
        level=str(raw["level"]),
        tags=tuple(str(x) for x in raw.get("tags", [])),
        falsepositives=tuple(str(x) for x in raw.get("falsepositives", [])),
        description=str(raw.get("description", "")),
    )


def load_rules(directory: str | Path) -> list[DetectionRule]:
    directory = Path(directory)
    rules = [load_rule(path) for path in sorted(directory.glob("*.yml"))]
    ids = [rule.id for rule in rules]
    duplicates = sorted({rid for rid in ids if ids.count(rid) > 1})
    if duplicates:
        raise ValueError(f"duplicate rule IDs: {', '.join(duplicates)}")
    return rules


def _field_parts(raw_key: str) -> tuple[str, str]:
    if "|" not in raw_key:
        return raw_key, "equals"
    field, modifier = raw_key.split("|", 1)
    return field, modifier


def _value_matches(actual: Any, expected: Any, modifier: str) -> bool:
    values = expected if isinstance(expected, list) else [expected]
    if modifier == "equals":
        return actual in values
    actual_s = "" if actual is None else str(actual).lower()
    expected_s = [str(v).lower() for v in values]
    if modifier == "contains":
        return any(v in actual_s for v in expected_s)
    if modifier == "startswith":
        return any(actual_s.startswith(v) for v in expected_s)
    if modifier == "endswith":
        return any(actual_s.endswith(v) for v in expected_s)
    raise ValueError(f"unsupported Sigma modifier: {modifier}")


def selector_matches(selector: dict[str, Any], fields: dict[str, Any]) -> bool:
    for raw_key, expected in selector.items():
        field, modifier = _field_parts(str(raw_key))
        if not _value_matches(fields.get(field), expected, modifier):
            return False
    return True


def rule_matches(rule: DetectionRule, fields: dict[str, Any]) -> bool:
    detection = rule.detection
    selector_results = {
        name: selector_matches(value, fields)
        for name, value in detection.items()
        if name != "condition"
        if isinstance(value, dict)
    }
    condition = str(detection["condition"]).strip()
    if condition in selector_results:
        return selector_results[condition]
    if condition.startswith("1 of "):
        prefix = condition.removeprefix("1 of ").rstrip("*")
        return any(value for name, value in selector_results.items() if name.startswith(prefix))
    if condition.startswith("all of "):
        prefix = condition.removeprefix("all of ").rstrip("*")
        selected = [value for name, value in selector_results.items() if name.startswith(prefix)]
        return bool(selected) and all(selected)
    if " and " in condition:
        names = [part.strip() for part in condition.split(" and ")]
        return all(selector_results.get(name, False) for name in names)
    if " or " in condition:
        names = [part.strip() for part in condition.split(" or ")]
        return any(selector_results.get(name, False) for name in names)
    raise ValueError(f"unsupported condition: {condition}")
