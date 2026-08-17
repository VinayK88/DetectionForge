from __future__ import annotations

from dataclasses import asdict, dataclass
import math

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

from .models import DetectionRule, TelemetryEvent
from .rules import rule_matches

MODEL_NAME = "GradientBoostingClassifier"
MODEL_VERSION = "detectionforge-alert-ranker-v1"
RANDOM_STATE = 17

FEATURE_NAMES = (
    "source_endpoint",
    "source_entra",
    "event_oauth_consent",
    "event_process_creation",
    "event_authentication",
    "rule_match_count",
    "max_rule_severity",
    "field_count",
    "new_device",
    "sensitive_access",
    "publisher_unverified",
    "tenant_wide_consent",
    "identity_risk_level",
    "encoded_command",
    "network_utility",
    "sensitive_oauth_scope_count",
    "log_text_volume",
)

_LEVEL = {"informational": 0.1, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


@dataclass(frozen=True)
class AlertPriority:
    event_id: str
    scenario: str
    probability: float
    uncertainty: float
    rule_match_count: int
    malicious_label: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _text(event: TelemetryEvent) -> str:
    return " ".join(str(value) for value in event.fields.values()).lower()


def feature_vector(event: TelemetryEvent, rules: list[DetectionRule]) -> np.ndarray:
    text = _text(event)
    matched = [rule for rule in rules if rule_matches(rule, event.fields)]
    max_severity = max((_LEVEL.get(rule.level.lower(), 0.25) for rule in matched), default=0.0)
    risk = str(event.fields.get("RiskLevel", "")).lower()
    risk_level = {"low": 0.2, "medium": 0.6, "high": 1.0}.get(risk, 0.0)
    permission = str(event.fields.get("Permission", "")).lower()
    sensitive_scopes = sum(
        token in permission
        for token in ("mail.readwrite", "files.readwrite.all", "directory.readwrite.all", "offline_access")
    )
    encoded = any(token in text for token in (" -enc ", "-encodedcommand", "frombase64string"))
    network = any(token in text for token in ("invoke-webrequest", "curl ", "wget ", "http://", "https://"))
    return np.asarray(
        [
            float(event.source == "endpoint"),
            float(event.source == "entra"),
            float(event.event_type == "oauth_consent"),
            float(event.event_type == "process_creation"),
            float(event.event_type == "authentication"),
            float(len(matched)),
            float(max_severity),
            float(len(event.fields)),
            float(bool(event.fields.get("NewDevice", False))),
            float(bool(event.fields.get("SensitiveAccess", False))),
            float(event.fields.get("AppVerified") is False),
            float(str(event.fields.get("ConsentType", "")) == "AllPrincipals"),
            float(risk_level),
            float(encoded),
            float(network),
            float(sensitive_scopes),
            float(math.log1p(len(text))),
        ],
        dtype=float,
    )


def _dataset(events: list[TelemetryEvent], rules: list[DetectionRule]) -> tuple[np.ndarray, np.ndarray]:
    x = np.vstack([feature_vector(event, rules) for event in events])
    y = np.asarray([int(event.malicious) for event in events], dtype=int)
    return x, y


def train_alert_ranker(events: list[TelemetryEvent], rules: list[DetectionRule]):
    x, y = _dataset(events, rules)
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.30,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    model = GradientBoostingClassifier(
        n_estimators=90,
        learning_rate=0.05,
        max_depth=2,
        random_state=RANDOM_STATE,
    )
    model.fit(x_train, y_train)
    prediction = model.predict(x_test)
    probability = model.predict_proba(x_test)[:, 1]
    metrics = {
        "model": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "train_samples": int(len(x_train)),
        "test_samples": int(len(x_test)),
        "precision": round(float(precision_score(y_test, prediction, zero_division=0)), 3),
        "recall": round(float(recall_score(y_test, prediction, zero_division=0)), 3),
        "f1": round(float(f1_score(y_test, prediction, zero_division=0)), 3),
        "roc_auc": round(float(roc_auc_score(y_test, probability)), 3),
        "boundary": "Synthetic replay labels validate the pipeline only; metrics are not production detection efficacy.",
    }
    model.fit(x, y)
    return model, metrics


def rank_events(events: list[TelemetryEvent], rules: list[DetectionRule]) -> list[AlertPriority]:
    if not events:
        return []
    model, _ = train_alert_ranker(events, rules)
    x, _ = _dataset(events, rules)
    probabilities = model.predict_proba(x)[:, 1]
    rows: list[AlertPriority] = []
    for event, vector, probability in zip(events, x, probabilities):
        rule_count = int(vector[FEATURE_NAMES.index("rule_match_count")])
        if rule_count == 0:
            continue
        p = float(probability)
        rows.append(
            AlertPriority(
                event_id=event.event_id,
                scenario=event.scenario,
                probability=round(p, 4),
                uncertainty=round(1.0 - abs(p - 0.5) * 2.0, 4),
                rule_match_count=rule_count,
                malicious_label=event.malicious,
            )
        )
    return sorted(rows, key=lambda row: (row.probability, row.rule_match_count, row.event_id), reverse=True)


def active_learning_candidates(
    events: list[TelemetryEvent], rules: list[DetectionRule], limit: int = 5
) -> list[AlertPriority]:
    """Return fired alerts closest to the decision boundary for analyst labeling."""
    ranked = rank_events(events, rules)
    return sorted(ranked, key=lambda row: (-row.uncertainty, row.event_id))[:limit]


def ml_report(events: list[TelemetryEvent], rules: list[DetectionRule]) -> dict[str, object]:
    _, metrics = train_alert_ranker(events, rules)
    ranked = rank_events(events, rules)
    candidates = active_learning_candidates(events, rules)
    return {
        "model": metrics,
        "features": list(FEATURE_NAMES),
        "ranked_alerts": [row.to_dict() for row in ranked[:10]],
        "active_learning_candidates": [row.to_dict() for row in candidates],
        "decision_boundary": "Rules decide coverage and release gates; ML prioritizes fired alerts and proposes uncertain cases for analyst review.",
    }
