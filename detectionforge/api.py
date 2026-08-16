from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .compiler import compile_kql
from .coverage import attack_coverage
from .replay import evaluate_rule, load_events
from .rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "detections")
EVENTS = load_events(ROOT / "data" / "telemetry.jsonl")

app = FastAPI(title="DetectionForge", version="0.1.0")


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    runs = [evaluate_rule(rule, EVENTS) for rule in RULES]
    rows = "".join(
        f"<tr><td>{rule.title}</td><td>{run.precision:.0%}</td><td>{run.recall:.0%}</td>"
        f"<td>{run.false_positive_rate:.1%}</td><td>{'PASS' if run.gate_passed else 'FAIL'}</td></tr>"
        for rule, run in zip(RULES, runs)
    )
    return f"""
    <html><head><title>DetectionForge</title><style>
    body{{font-family:system-ui;max-width:1050px;margin:40px auto;padding:0 20px;color:#111827}}
    table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}
    code{{background:#f3f4f6;padding:2px 5px;border-radius:4px}}
    </style></head><body>
    <h1>DetectionForge</h1><p>Detection-as-code quality gate for synthetic attack and benign replay.</p>
    <table><thead><tr><th>Detection</th><th>Precision</th><th>Recall</th><th>FPR</th><th>Gate</th></tr></thead><tbody>{rows}</tbody></table>
    <p>Inspect <code>/rules</code>, <code>/coverage</code>, or <code>/compile/{{rule_id}}</code>.</p>
    </body></html>"""


@app.get("/rules")
def rules():
    return [asdict(evaluate_rule(rule, EVENTS)) for rule in RULES]


@app.get("/coverage")
def coverage():
    return attack_coverage(RULES)


@app.get("/compile/{rule_id}")
def compile_rule(rule_id: str):
    for rule in RULES:
        if rule.id == rule_id:
            return {"rule_id": rule.id, "kql": compile_kql(rule)}
    raise HTTPException(status_code=404, detail="unknown rule_id")
