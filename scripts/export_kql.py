from __future__ import annotations

from pathlib import Path

from detectionforge.compiler import compile_kql
from detectionforge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
out = ROOT / "reports" / "compiled-kql"
out.mkdir(parents=True, exist_ok=True)
for rule in load_rules(ROOT / "detections"):
    path = out / f"{rule.id}.kql"
    path.write_text(compile_kql(rule) + "\n", encoding="utf-8")
    print(path.relative_to(ROOT))
