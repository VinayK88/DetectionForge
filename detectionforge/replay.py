from __future__ import annotations

import json
from pathlib import Path

from .models import DetectionRule, RuleRun, TelemetryEvent
from .rules import rule_matches


def load_events(path: str | Path) -> list[TelemetryEvent]:
    events: list[TelemetryEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        events.append(
            TelemetryEvent(
                event_id=str(raw["event_id"]),
                source=str(raw["source"]),
                event_type=str(raw["event_type"]),
                timestamp=str(raw["timestamp"]),
                fields=dict(raw["fields"]),
                malicious=bool(raw["malicious"]),
                scenario=str(raw["scenario"]),
            )
        )
    return events


def _ratio(num: int, den: int) -> float:
    return num / den if den else 0.0


def evaluate_rule(
    rule: DetectionRule,
    events: list[TelemetryEvent],
    *,
    min_precision: float = 0.80,
    min_recall: float = 0.80,
    max_fpr: float = 0.10,
) -> RuleRun:
    relevant = [
        event for event in events
        if event.source == str(rule.logsource.get("product", event.source))
        and (not rule.logsource.get("category") or event.event_type == rule.logsource.get("category"))
    ]
    matches = [event for event in relevant if rule_matches(rule, event.fields)]
    matched_ids = {event.event_id for event in matches}
    tp = sum(event.malicious and event.event_id in matched_ids for event in relevant)
    fp = sum((not event.malicious) and event.event_id in matched_ids for event in relevant)
    fn = sum(event.malicious and event.event_id not in matched_ids for event in relevant)
    tn = sum((not event.malicious) and event.event_id not in matched_ids for event in relevant)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    fpr = _ratio(fp, fp + tn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    reasons: list[str] = []
    if precision < min_precision:
        reasons.append(f"precision {precision:.3f} < {min_precision:.3f}")
    if recall < min_recall:
        reasons.append(f"recall {recall:.3f} < {min_recall:.3f}")
    if fpr > max_fpr:
        reasons.append(f"false_positive_rate {fpr:.3f} > {max_fpr:.3f}")
    return RuleRun(
        rule_id=rule.id,
        matched_event_ids=tuple(sorted(matched_ids)),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        specificity=specificity,
        false_positive_rate=fpr,
        f1=f1,
        gate_passed=not reasons,
        gate_reasons=tuple(reasons),
    )
