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


def _surface(rule) -> str:
    product = str(rule.logsource.get("product", "unknown"))
    category = str(rule.logsource.get("category", "events"))
    return f"{product} / {category}"


def _metric_bar(value: float, *, inverse: bool = False) -> str:
    score = (1 - value if inverse else value) * 100
    width = max(0.0, min(score, 100.0))
    return f'<div class="meter"><span style="width:{width:.1f}%"></span></div>'


def _rule_card(rule, run) -> str:
    gate_class = "pass" if run.gate_passed else "fail"
    gate_text = "Release gate passed" if run.gate_passed else "Release gate failed"
    techniques = "".join(
        f'<span class="chip attack">{escape(technique)}</span>' for technique in rule.attack_techniques
    ) or '<span class="chip muted">No ATT&amp;CK tag</span>'

    false_positive_text = ", ".join(rule.falsepositives[:2]) if rule.falsepositives else "No examples documented"
    return f"""
    <article class="rule-card" data-gate="{gate_class}" data-surface="{escape(str(rule.logsource.get('product', 'unknown')))}">
      <div class="rule-head">
        <div>
          <div class="eyebrow">{escape(rule.id)} · {escape(rule.level.upper())}</div>
          <h3>{escape(rule.title)}</h3>
          <p class="surface">{escape(_surface(rule))}</p>
        </div>
        <span class="status {gate_class}">{gate_text}</span>
      </div>
      <div class="rule-metrics">
        <div><span>Precision</span><strong>{_pct(run.precision)}</strong>{_metric_bar(run.precision)}</div>
        <div><span>Recall</span><strong>{_pct(run.recall)}</strong>{_metric_bar(run.recall)}</div>
        <div><span>False-positive rate</span><strong>{_pct(run.false_positive_rate)}</strong>{_metric_bar(run.false_positive_rate, inverse=True)}</div>
        <div><span>F1</span><strong>{_pct(run.f1)}</strong>{_metric_bar(run.f1)}</div>
      </div>
      <div class="rule-foot">
        <div><span class="label">Coverage</span>{techniques}</div>
        <div><span class="label">Benign lookalikes</span><span>{escape(false_positive_text)}</span></div>
        <div class="actions"><a href="/compile/{escape(rule.id)}">View compiled KQL</a></div>
      </div>
    </article>
    """


def _feedback_rows() -> str:
    rows: list[str] = []
    for rule in RULES:
        summary = summarize_feedback(FEEDBACK_PATH, rule.id)
        precision = "—" if summary.analyst_precision is None else _pct(summary.analyst_precision)
        reasons = ", ".join(reason for reason, _ in summary.common_benign_reasons) or "—"
        rows.append(
            "<tr>"
            f"<td><strong>{escape(rule.title)}</strong><br><span class='mono'>{escape(rule.id)}</span></td>"
            f"<td>{summary.reviewed}</td>"
            f"<td>{summary.true_positive}</td>"
            f"<td>{summary.benign}</td>"
            f"<td>{precision}</td>"
            f"<td>{escape(reasons)}</td>"
            "</tr>"
        )
    return "".join(rows)


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
    attack_rows = "".join(
        f"<div class='coverage-row'><span class='technique'>{escape(technique)}</span>"
        f"<span>{len(rule_ids)} detection{'s' if len(rule_ids) != 1 else ''}</span>"
        f"<span class='mono'>{escape(', '.join(rule_ids))}</span></div>"
        for technique, rule_ids in coverage.items()
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DetectionForge · Detection Engineering Scorecard</title>
<style>
:root {{
  --bg:#07101f; --panel:#0d1728; --panel2:#111d31; --line:#24324a; --text:#edf3ff;
  --muted:#9eabc1; --accent:#7c8cff; --accent2:#3dd9b2; --warn:#f2b84b; --bad:#ff6b7a;
}}
*{{box-sizing:border-box}} body{{margin:0;background:linear-gradient(180deg,#07101f 0%,#091321 48%,#08101c 100%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
a{{color:#aeb8ff;text-decoration:none}} a:hover{{text-decoration:underline}}
.shell{{max-width:1220px;margin:0 auto;padding:0 28px 60px}}
.topbar{{display:flex;justify-content:space-between;align-items:center;padding:22px 0;border-bottom:1px solid var(--line)}}
.brand{{display:flex;gap:12px;align-items:center;font-weight:800;letter-spacing:-.02em}} .mark{{display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,#7587ff,#3dd9b2);color:#07101f;font-weight:950}}
.nav{{display:flex;gap:22px;font-size:14px;color:var(--muted)}} .nav a{{color:var(--muted)}}
.hero{{display:grid;grid-template-columns:1.35fr .65fr;gap:28px;align-items:stretch;padding:54px 0 34px}}
.hero h1{{font-size:clamp(40px,6vw,72px);line-height:.98;letter-spacing:-.055em;margin:10px 0 20px;max-width:780px}}
.hero p{{font-size:18px;line-height:1.65;color:#b8c4d8;max-width:760px}}
.kicker{{font-size:12px;text-transform:uppercase;letter-spacing:.18em;color:var(--accent2);font-weight:800}}
.hero-panel{{background:radial-gradient(circle at top right,rgba(124,140,255,.23),transparent 42%),var(--panel);border:1px solid var(--line);border-radius:20px;padding:24px;display:flex;flex-direction:column;justify-content:space-between}}
.pipeline{{display:grid;gap:9px;margin-top:16px}} .pipe{{padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#0a1424;color:#c9d4e7;font-size:13px}} .arrow{{text-align:center;color:#596982;height:8px}}
.grid4{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:10px 0 38px}} .kpi{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:20px}} .kpi span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}} .kpi strong{{display:block;font-size:30px;margin-top:8px;letter-spacing:-.04em}} .kpi small{{display:block;color:#77869e;margin-top:5px}}
.section{{margin-top:44px}} .section-head{{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:18px}} .section h2{{font-size:26px;letter-spacing:-.03em;margin:0}} .section-head p{{color:var(--muted);margin:0;max-width:570px;font-size:14px;line-height:1.5}}
.toolbar{{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}} button.filter{{border:1px solid var(--line);background:#0b1626;color:#aebbd1;padding:8px 12px;border-radius:999px;cursor:pointer}} button.filter.active{{background:#202c58;color:white;border-color:#6878e8}}
.rules{{display:grid;gap:16px}} .rule-card{{background:linear-gradient(180deg,#0e192b,#0b1525);border:1px solid var(--line);border-radius:18px;padding:22px;box-shadow:0 14px 40px rgba(0,0,0,.12)}}
.rule-head{{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}} .rule-head h3{{margin:5px 0;font-size:20px;letter-spacing:-.02em}} .eyebrow{{font-size:11px;color:#7f90ad;text-transform:uppercase;letter-spacing:.11em}} .surface{{color:var(--muted);font-size:13px;margin:0}}
.status{{font-size:12px;font-weight:800;padding:7px 10px;border-radius:999px;white-space:nowrap}} .status.pass{{background:rgba(61,217,178,.12);color:#68e4c5;border:1px solid rgba(61,217,178,.28)}} .status.fail{{background:rgba(255,107,122,.12);color:#ff8b98;border:1px solid rgba(255,107,122,.28)}}
.rule-metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:22px;margin:22px 0 20px;padding:18px 0;border-top:1px solid #1c2940;border-bottom:1px solid #1c2940}} .rule-metrics span{{display:block;color:var(--muted);font-size:12px}} .rule-metrics strong{{font-size:22px;display:block;margin:4px 0 8px}}
.meter{{height:5px;background:#1c2940;border-radius:20px;overflow:hidden}} .meter span{{display:block;height:100%;background:linear-gradient(90deg,#697cff,#41d3b1);border-radius:20px}}
.rule-foot{{display:grid;grid-template-columns:1fr 1.5fr auto;gap:18px;align-items:center;color:#aab7ca;font-size:13px}} .label{{display:block;color:#6f7f99;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}} .chip{{display:inline-flex;padding:5px 8px;border-radius:8px;margin-right:5px;font-size:11px}} .chip.attack{{background:#172c3c;color:#77e1cb;border:1px solid #22485a}} .chip.muted{{background:#162033;color:#8da0bb}}
.actions a{{display:inline-flex;border:1px solid #33425f;padding:8px 11px;border-radius:9px}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:18px}} .panel{{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:22px}} .panel h3{{margin-top:0}}
.coverage-row{{display:grid;grid-template-columns:110px 120px 1fr;gap:12px;padding:12px 0;border-bottom:1px solid #1d2a40;font-size:13px;color:#aebbd0}} .coverage-row:last-child{{border-bottom:0}} .technique{{font-weight:800;color:#79ddc7}}
.table-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:16px}} table{{border-collapse:collapse;width:100%;background:var(--panel)}} th,td{{padding:13px 14px;border-bottom:1px solid #1d2a40;text-align:left;font-size:13px}} th{{color:#8090a9;font-size:10px;text-transform:uppercase;letter-spacing:.08em;background:#0a1423}} td{{color:#bcc8da}} tr:last-child td{{border-bottom:0}} .mono{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#8191ab}}
.boundary{{border-left:3px solid var(--warn);padding:14px 18px;background:rgba(242,184,75,.05);border-radius:0 12px 12px 0;color:#b9c5d7;line-height:1.6;font-size:14px}}
.footer{{border-top:1px solid var(--line);margin-top:50px;padding-top:22px;display:flex;justify-content:space-between;gap:20px;color:#6e7e97;font-size:12px}}
@media(max-width:900px){{.hero,.two-col{{grid-template-columns:1fr}}.grid4{{grid-template-columns:repeat(2,1fr)}}.rule-metrics{{grid-template-columns:repeat(2,1fr)}}.rule-foot{{grid-template-columns:1fr}}.nav{{display:none}}}}
@media(max-width:560px){{.shell{{padding:0 16px 40px}}.grid4{{grid-template-columns:1fr}}.hero{{padding-top:36px}}.hero h1{{font-size:44px}}}}
</style>
</head>
<body>
<div class="shell">
  <header class="topbar">
    <div class="brand"><span class="mark">DF</span><span>DetectionForge</span></div>
    <nav class="nav"><a href="#scorecard">Scorecard</a><a href="#coverage">ATT&amp;CK</a><a href="#feedback">Feedback</a><a href="/docs">API docs</a></nav>
  </header>

  <section class="hero">
    <div>
      <div class="kicker">Detection engineering · release quality</div>
      <h1>Ship detections with evidence, not intuition.</h1>
      <p>DetectionForge treats security detections like production code: versioned rules are compiled, replayed against malicious and benign lookalikes, measured, gated in CI, mapped to ATT&amp;CK, and improved with analyst dispositions.</p>
    </div>
    <aside class="hero-panel">
      <div>
        <div class="kicker">Release workflow</div>
        <div class="pipeline">
          <div class="pipe">01 · Author Sigma-style detection</div><div class="arrow">↓</div>
          <div class="pipe">02 · Compile to reviewable KQL</div><div class="arrow">↓</div>
          <div class="pipe">03 · Replay attack + benign telemetry</div><div class="arrow">↓</div>
          <div class="pipe">04 · Gate on precision / recall / FPR</div><div class="arrow">↓</div>
          <div class="pipe">05 · Feed analyst dispositions back</div>
        </div>
      </div>
    </aside>
  </section>

  <section class="grid4" aria-label="Portfolio summary">
    <div class="kpi"><span>Release-ready rules</span><strong>{passing}/{len(runs)}</strong><small>current synthetic regression gate</small></div>
    <div class="kpi"><span>Mean precision</span><strong>{_pct(avg_precision)}</strong><small>across checked-in detections</small></div>
    <div class="kpi"><span>Mean recall</span><strong>{_pct(avg_recall)}</strong><small>against malicious replay fixtures</small></div>
    <div class="kpi"><span>ATT&amp;CK coverage</span><strong>{len(coverage)}</strong><small>techniques with mapped detections</small></div>
  </section>

  <section class="section" id="scorecard">
    <div class="section-head"><div><div class="kicker">Detection health</div><h2>Release scorecard</h2></div><p>{len(EVENTS)} deterministic replay events: {malicious} malicious scenarios and {benign} benign / hard-negative events.</p></div>
    <div class="toolbar">
      <button class="filter active" onclick="filterRules('all',this)">All detections</button>
      <button class="filter" onclick="filterRules('pass',this)">Passing</button>
      <button class="filter" onclick="filterRules('entra',this)">Entra</button>
      <button class="filter" onclick="filterRules('endpoint',this)">Endpoint</button>
    </div>
    <div class="rules" id="rule-list">{rule_cards}</div>
  </section>

  <section class="section two-col" id="coverage">
    <div class="panel"><div class="kicker">Coverage</div><h3>MITRE ATT&amp;CK map</h3>{attack_rows}</div>
    <div class="panel"><div class="kicker">Quality gate</div><h3>What blocks a release?</h3>
      <div class="coverage-row"><span>Precision</span><span>≥ 80%</span><span>controls analyst noise</span></div>
      <div class="coverage-row"><span>Recall</span><span>≥ 80%</span><span>protects against missed malicious replay</span></div>
      <div class="coverage-row"><span>FPR</span><span>≤ 10%</span><span>guards benign hard negatives</span></div>
      <div class="coverage-row"><span>CI</span><span>3.10–3.12</span><span>tests · validate · evaluate · compile</span></div>
    </div>
  </section>

  <section class="section" id="feedback">
    <div class="section-head"><div><div class="kicker">Operational loop</div><h2>Analyst feedback</h2></div><p>Human dispositions remain separate from synthetic ground truth, so production feedback can tune detections without contaminating the offline benchmark.</p></div>
    <div class="table-wrap"><table><thead><tr><th>Detection</th><th>Reviewed</th><th>True positive</th><th>Benign</th><th>Analyst precision</th><th>Common benign reason</th></tr></thead><tbody>{_feedback_rows()}</tbody></table></div>
  </section>

  <section class="section">
    <div class="boundary"><strong>Evaluation boundary.</strong> All checked-in telemetry, identities, applications, commands, URLs, and labels are synthetic. These measurements demonstrate detection-engineering methodology and regression behavior; they are not claims of production efficacy.</div>
  </section>

  <footer class="footer"><span>DetectionForge · detection engineering as code</span><span><a href="/rules">JSON scorecard</a> · <a href="/coverage">coverage API</a> · <a href="/docs">OpenAPI</a></span></footer>
</div>
<script>
function filterRules(filter, button) {
  document.querySelectorAll('.filter').forEach(b => b.classList.remove('active'));
  button.classList.add('active');
  document.querySelectorAll('.rule-card').forEach(card => {
    const gate = card.dataset.gate;
    const surface = card.dataset.surface.toLowerCase();
    const show = filter === 'all' || gate === filter || surface.includes(filter);
    card.style.display = show ? '' : 'none';
  });
}
</script>
</body></html>"""


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
