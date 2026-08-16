from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DetectionRule:
    id: str
    title: str
    status: str
    logsource: dict[str, Any]
    detection: dict[str, Any]
    level: str
    tags: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    description: str = ""

    @property
    def attack_techniques(self) -> tuple[str, ...]:
        out: list[str] = []
        for tag in self.tags:
            if tag.startswith("attack.t"):
                technique = tag.removeprefix("attack.").upper()
                out.append(technique)
        return tuple(out)


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    source: str
    event_type: str
    timestamp: str
    fields: dict[str, Any]
    malicious: bool
    scenario: str


@dataclass(frozen=True)
class RuleRun:
    rule_id: str
    matched_event_ids: tuple[str, ...]
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    specificity: float
    false_positive_rate: float
    f1: float
    gate_passed: bool
    gate_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class FeedbackSummary:
    rule_id: str
    reviewed: int
    true_positive: int
    benign: int
    unknown: int
    analyst_precision: float | None
    common_benign_reasons: tuple[tuple[str, int], ...] = field(default_factory=tuple)
