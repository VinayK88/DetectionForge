from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import FeedbackSummary


def summarize_feedback(path: str | Path, rule_id: str) -> FeedbackSummary:
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    selected = [row for row in rows if row.get("rule_id") == rule_id]
    dispositions = Counter(str(row.get("disposition", "unknown")) for row in selected)
    benign_reasons = Counter(
        str(row.get("reason", "unspecified"))
        for row in selected
        if row.get("disposition") == "benign"
    )
    reviewed = len(selected)
    tp = dispositions["true_positive"]
    benign = dispositions["benign"]
    denom = tp + benign
    precision = tp / denom if denom else None
    return FeedbackSummary(
        rule_id=rule_id,
        reviewed=reviewed,
        true_positive=tp,
        benign=benign,
        unknown=dispositions["unknown"],
        analyst_precision=precision,
        common_benign_reasons=tuple(benign_reasons.most_common(5)),
    )
