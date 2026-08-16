from __future__ import annotations

from typing import Any

from .models import DetectionRule


def _quote(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace('"', '\\"') + '"'


def _compile_field(raw_key: str, expected: Any) -> str:
    if "|" in raw_key:
        field, modifier = raw_key.split("|", 1)
    else:
        field, modifier = raw_key, "equals"
    values = expected if isinstance(expected, list) else [expected]
    pieces: list[str] = []
    for value in values:
        if modifier == "equals":
            pieces.append(f"{field} == {_quote(value)}")
        elif modifier == "contains":
            pieces.append(f"{field} contains {_quote(value)}")
        elif modifier == "startswith":
            pieces.append(f"{field} startswith {_quote(value)}")
        elif modifier == "endswith":
            pieces.append(f"{field} endswith {_quote(value)}")
        else:
            raise ValueError(f"unsupported Sigma modifier for KQL: {modifier}")
    return "(" + " or ".join(pieces) + ")"


def _compile_selector(selector: dict[str, Any]) -> str:
    return " and ".join(_compile_field(str(k), v) for k, v in selector.items())


def compile_kql(rule: DetectionRule) -> str:
    selectors = {
        name: _compile_selector(value)
        for name, value in rule.detection.items()
        if name != "condition" and isinstance(value, dict)
    }
    condition = str(rule.detection["condition"]).strip()
    if condition in selectors:
        predicate = selectors[condition]
    elif condition.startswith("1 of "):
        prefix = condition.removeprefix("1 of ").rstrip("*")
        selected = [value for name, value in selectors.items() if name.startswith(prefix)]
        predicate = " or ".join(f"({x})" for x in selected)
    elif condition.startswith("all of "):
        prefix = condition.removeprefix("all of ").rstrip("*")
        selected = [value for name, value in selectors.items() if name.startswith(prefix)]
        predicate = " and ".join(f"({x})" for x in selected)
    elif " and " in condition:
        predicate = " and ".join(f"({selectors[name.strip()]})" for name in condition.split(" and "))
    elif " or " in condition:
        predicate = " or ".join(f"({selectors[name.strip()]})" for name in condition.split(" or "))
    else:
        raise ValueError(f"unsupported condition for KQL: {condition}")

    table = str(rule.logsource.get("table", "SecurityEvent"))
    projection = "TimeGenerated, EventId, Account, DeviceName, ActionType, IPAddress, Application, CommandLine"
    return (
        f"// {rule.title}\n"
        f"// DetectionForge rule_id={rule.id}\n"
        f"{table}\n"
        f"| where {predicate}\n"
        f"| project {projection}"
    )
