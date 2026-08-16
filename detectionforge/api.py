from __future__ import annotations

from dataclasses import asdict
from html import escape
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .compiler import compile_kql
from .coverage import attack_coverage
from .feedback import summarize_feedback
from .replay import evaluate_rule, load_events
from .rules import load_rules

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "detections")
EVENTS = load_events(ROOT / "data" / "telemetry.jsonl")
FEEDBACK_PATH = ROOT / "data" / "analyst_feedback.json"

app = FastAPI(
    title="DetectionForge",
    version="0.1.0",
    description="Detection-as-code quality gates for versioned security detections.",
)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _metric(value: float, inverse: bool = False) -> str:
    width = (1 - value if inverse else value) * 100
    width = max(0.0, min(width, 100.0))
    return f'<div class="meter"><i style="width:{width:.1f}%"></i></div>'


def _rule_card(rule, run) -> str:
    state = "pass" if run.gate_passed else "fail"
    techniques = " ".join(
        f'<span class="chip">{escape(item)}</span>' for item in rule.attack_techniques
    )
    lookalikes = ", ".join(rule.falsepositives[:2]) or "No examples documented"
    surface = f"{rule.logsource.get('product', 'unknown')} / {rule.logsource.get('category', 'events')}"
    return f"""
    <article class="rule">
      <div class="rule-top">
        <div><small>{escape(rule.id)} · {escape(rule.level.upper())}</small><h3>{escape(rule.title)}</h3><p>{escape(surface)}</p></div>
        <span class="status {state}">{'Release gate passed' if run.gate_passed else 'Release gate failed'}</span>
      </div>
      <div class="metrics">
        <div><label>Precision</label><b>{_pct(run.precision)}</b>{_metric(run.precision)}</div>
        <div><label>Recall</label><b>{_pct(run.recall)}</b>{_metric(run.recall)}</div>
        <div><label>False-positive rate</label><b>{_pct(run.false_positive_rate)}</b>{_metric(run.false_positive_rate, True)}</div>
        <div><label>F1</label><b>{_pct(run.f1)}</b>{_metric(run.f1)}</div>
      </div>
      <div class="rule-bottom"><div><label>ATT&amp;CK</label>{techniques}</div><div><label>Benign lookalikes</label>{escape(lookalikes)}</div><a href="/compile/{escape(rule.id)}">Compiled KQL →</a></div>
    </article>"""


def _feedback_rows() -> str:
    rows = []
    for rule in RULES:
        summary = summarize_feedback(FEEDBACK_PATH, rule.id)
        analyst_precision = "—" if summary.analyst_precision is None else _pct(summary.analyst_precision)
        reasons = ", ".join(reason for reason, _ in summary.common_benign_reasons) or "—"
        rows.append(
            f"<tr><td><b>{escape(rule.title)}</b><small>{escape(rule.id)}</small></td>"
            f"<td>{summary.reviewed}</td><td>{summary.true_positive}</td><td>{summary.benign}</td>"
            f"<td>{analyst_precision}</td><td>{escape(reasons)}</td></tr>"
        )
    return "".join(rows)


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DetectionForge · Detection Engineering Scorecard</title>
<style>
:root{--bg:#07101f;--panel:#0d1829;--line:#22314a;--text:#edf3ff;--muted:#94a3ba;--accent:#7182ff;--green:#42d8b4;--red:#ff7180;--yellow:#f2bd54}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#07101f,#091422 65%,#07101d);color:var(--text);font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif}a{color:#b1bbff;text-decoration:none}.wrap{max-width:1180px;margin:auto;padding:0 26px 54px}.nav{height:76px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px;font-weight:800}.mark{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--green));color:#07101f}.links{display:flex;gap:20px;font-size:13px}.hero{display:grid;grid-template-columns:1.4fr .6fr;gap:28px;padding:52px 0 32px}.eyebrow{color:var(--green);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}.hero h1{font-size:58px;line-height:1;letter-spacing:-.05em;margin:10px 0 18px}.hero p{max-width:720px;color:#b5c0d4;font-size:17px;line-height:1.65}.workflow,.card,.rule,.panel{background:var(--panel);border:1px solid var(--line);border-radius:17px}.workflow{padding:22px}.flow{margin-top:14px;display:grid;gap:8px}.flow span{border:1px solid var(--line);background:#091525;padding:9px 11px;border-radius:9px;color:#bac6d9;font-size:12px}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:42px}.card{padding:18px}.card label,.metrics label,.rule-bottom label{display:block;color:#75859f;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.card b{display:block;font-size:28px;margin:7px 0 3px}.card small{color:#687891}.section{margin-top:42px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:16px}.section h2{margin:4px 0 0;font-size:26px}.section-head p{color:var(--muted);font-size:13px;max-width:520px}.rules{display:grid;gap:15px}.rule{padding:20px}.rule-top{display:flex;justify-content:space-between;gap:16px}.rule-top small{color:#71819c;font-size:10px;letter-spacing:.08em}.rule h3{margin:5px 0;font-size:19px}.rule p{margin:0;color:var(--muted);font-size:12px}.status{font-size:11px;font-weight:800;border-radius:999px;padding:7px 10px;height:max-content}.pass{background:#10362f;color:#6ee4c7;border:1px solid #205d50}.fail{background:#3a1920;color:#ff9aa5;border:1px solid #67303a}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin:19px 0;padding:17px 0;border-top:1px solid #1d2b42;border-bottom:1px solid #1d2b42}.metrics b{display:block;font-size:21px;margin:4px 0 7px}.meter{height:4px;border-radius:9px;background:#1d2b42;overflow:hidden}.meter i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--green))}.rule-bottom{display:grid;grid-template-columns:1fr 1.6fr auto;gap:18px;align-items:center;color:#aebbd0;font-size:12px}.chip{display:inline-block;background:#12303a;color:#68dcc2;border:1px solid #21505b;border-radius:7px;padding:4px 7px;margin:5px 4px 0 0}.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{padding:20px}.coverage-row{display:grid;grid-template-columns:110px 110px 1fr;gap:12px;padding:11px 0;border-bottom:1px solid #1d2b42;color:#aab8cc;font-size:12px}.coverage-row:last-child{border:0}.tech{color:#65dbc2;font-weight:800}.table{overflow-x:auto;border:1px solid var(--line);border-radius:15px}table{width:100%;border-collapse:collapse;background:var(--panel)}th,td{text-align:left;padding:12px;border-bottom:1px solid #1d2b42;font-size:12px}th{background:#091525;color:#74849d;font-size:9px;letter-spacing:.07em;text-transform:uppercase}td{color:#b6c2d4}td small{display:block;color:#71819b;margin-top:3px}.boundary{border-left:3px solid var(--yellow);background:rgba(242,189,84,.05);padding:14px 16px;border-radius:0 11px 11px 0;color:#b7c3d5;font-size:13px;line-height:1.6}.footer{margin-top:42px;border-top:1px solid var(--line);padding-top:20px;color:#66768f;font-size:11px;display:flex;justify-content:space-between}.footer a{margin-left:12px}@media(max-width:850px){.hero,.two{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}.metrics{grid-template-columns:repeat(2,1fr)}.rule-bottom{grid-template-columns:1fr}.links{display:none}}@media(max-width:520px){.wrap{padding:0 16px 40px}.hero h1{font-size:42px}.kpis{grid-template-columns:1fr}}
</style></head><body><div class="wrap">
<header class="nav"><div class="brand"><span class="mark">DF</span>DetectionForge</div><nav class="links"><a href="#scorecard">Scorecard</a><a href="#coverage">ATT&amp;CK</a><a href="#feedback">Feedback</a><a href="/docs">API docs</a></nav></header>
<section class="hero"><div><div class="eyebrow">Detection engineering · release quality</div><h1>Ship detections with evidence, not intuition.</h1><p>Versioned detections are compiled, replayed against malicious and benign lookalikes, measured, gated in CI, mapped to ATT&amp;CK, and improved with analyst dispositions.</p></div><aside class="workflow"><div class="eyebrow">Release workflow</div><div class="flow"><span>01 · Author Sigma-style rule</span><span>02 · Compile to reviewable KQL</span><span>03 · Replay attack + benign telemetry</span><span>04 · Gate on precision / recall / FPR</span><span>05 · Feed analyst dispositions back</span></div></aside></section>
<section class="kpis"><div class="card"><label>Release-ready rules</label><b>__PASSING__/__RULE_COUNT__</b><small>current regression gate</small></div><div class="card"><label>Mean precision</label><b>__AVG_PRECISION__</b><small>across checked-in rules</small></div><div class="card"><label>Mean recall</label><b>__AVG_RECALL__</b><small>malicious replay fixtures</small></div><div class="card"><label>ATT&amp;CK coverage</label><b>__COVERAGE_COUNT__</b><small>mapped techniques</small></div></section>
<section class="section" id="scorecard"><div class="section-head"><div><div class="eyebrow">Detection health</div><h2>Release scorecard</h2></div><p>__EVENT_COUNT__ deterministic replay events: __MALICIOUS__ malicious and __BENIGN__ benign / hard-negative events.</p></div><div class="rules">__RULE_CARDS__</div></section>
<section class="section two" id="coverage"><div class="panel"><div class="eyebrow">Coverage</div><h2>MITRE ATT&amp;CK map</h2>__COVERAGE_ROWS__</div><div class="panel"><div class="eyebrow">Quality gate</div><h2>What blocks a release?</h2><div class="coverage-row"><span>Precision</span><b>≥ 80%</b><span>controls analyst noise</span></div><div class="coverage-row"><span>Recall</span><b>≥ 80%</b><span>protects malicious replay</span></div><div class="coverage-row"><span>FPR</span><b>≤ 10%</b><span>guards benign hard negatives</span></div><div class="coverage-row"><span>CI</span><b>3.10–3.12</b><span>test · validate · evaluate · compile</span></div></div></section>
<section class="section" id="feedback"><div class="section-head"><div><div class="eyebrow">Operational loop</div><h2>Analyst feedback</h2></div><p>Human dispositions stay separate from synthetic ground truth so tuning does not contaminate the offline benchmark.</p></div><div class="table"><table><thead><tr><th>Detection</th><th>Reviewed</th><th>TP</th><th>Benign</th><th>Analyst precision</th><th>Common benign reason</th></tr></thead><tbody>__FEEDBACK_ROWS__</tbody></table></div></section>
<section class="section"><div class="boundary"><b>Evaluation boundary.</b> All checked-in telemetry, identities, applications, commands, URLs, and labels are synthetic. These metrics demonstrate detection-engineering methodology and regression behavior; they are not production efficacy claims.</div></section>
<footer class="footer"><span>DetectionForge · detection engineering as code</span><span><a href="/rules">JSON scorecard</a><a href="/coverage">coverage API</a><a href="/docs">OpenAPI</a></span></footer>
</div></body></html>"""


@app.get("/", response_class=HTMLResponse)
def home() -> str:
    runs = [evaluate_rule(rule, EVENTS) for rule in RULES]
    coverage = attack_coverage(RULES)
    passing = sum(run.gate_passed for run in runs)
    malicious = sum(event.malicious for event in EVENTS)
    benign = len(EVENTS) - malicious
    avg_precision = sum(run.precision for run in runs) / len(runs) if runs else 0.0
    avg_recall = sum(run.recall for run in runs) / len(runs) if runs else 0.0

    rule_cards = "".join(_rule_card(rule, run) for rule, run in zip(RULES, runs))
    coverage_rows = "".join(
        f'<div class="coverage-row"><span class="tech">{escape(technique)}</span><span>{len(rule_ids)} detection</span><span>{escape(", ".join(rule_ids))}</span></div>'
        for technique, rule_ids in coverage.items()
    )

    replacements = {
        "__PASSING__": str(passing),
        "__RULE_COUNT__": str(len(runs)),
        "__AVG_PRECISION__": _pct(avg_precision),
        "__AVG_RECALL__": _pct(avg_recall),
        "__COVERAGE_COUNT__": str(len(coverage)),
        "__EVENT_COUNT__": str(len(EVENTS)),
        "__MALICIOUS__": str(malicious),
        "__BENIGN__": str(benign),
        "__RULE_CARDS__": rule_cards,
        "__COVERAGE_ROWS__": coverage_rows,
        "__FEEDBACK_ROWS__": _feedback_rows(),
    }
    page = HTML_TEMPLATE
    for marker, value in replacements.items():
        page = page.replace(marker, value)
    return page


@app.get("/healthz")
def healthz():
    return {"status": "ok", "rules": len(RULES), "events": len(EVENTS)}


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
