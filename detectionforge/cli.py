from __future__ import annotations

import argparse
import json
from pathlib import Path

from .compiler import compile_kql
from .coverage import attack_coverage
from .ml import ml_report
from .replay import evaluate_rule, load_events
from .report import build_report
from .rules import load_rule, load_rules


def _json_default(obj):
    if isinstance(obj, tuple):
        return list(obj)
    raise TypeError(type(obj).__name__)


def cmd_validate(args: argparse.Namespace) -> int:
    rules = load_rules(args.detections)
    print(f"validated {len(rules)} detection rules")
    return 0


def cmd_compile(args: argparse.Namespace) -> int:
    rule = load_rule(args.rule)
    print(compile_kql(rule))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    rules = load_rules(args.detections)
    events = load_events(args.events)
    runs = [
        evaluate_rule(
            rule,
            events,
            min_precision=args.min_precision,
            min_recall=args.min_recall,
            max_fpr=args.max_fpr,
        )
        for rule in rules
    ]
    report = build_report(rules, runs)
    rendered = json.dumps(report, indent=2, default=_json_default)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if all(run.gate_passed for run in runs) else 2


def cmd_ml_rank(args: argparse.Namespace) -> int:
    rules = load_rules(args.detections)
    events = load_events(args.events)
    report = ml_report(events, rules)
    rendered = json.dumps(report, indent=2, default=_json_default)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    print(json.dumps(attack_coverage(load_rules(args.detections)), indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="DetectionForge detection-as-code toolkit")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--detections", default="detections")
    validate.set_defaults(func=cmd_validate)

    compile_cmd = sub.add_parser("compile-kql")
    compile_cmd.add_argument("rule")
    compile_cmd.set_defaults(func=cmd_compile)

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--detections", default="detections")
    evaluate.add_argument("--events", default="data/telemetry.jsonl")
    evaluate.add_argument("--output")
    evaluate.add_argument("--min-precision", type=float, default=0.80)
    evaluate.add_argument("--min-recall", type=float, default=0.80)
    evaluate.add_argument("--max-fpr", type=float, default=0.10)
    evaluate.set_defaults(func=cmd_evaluate)

    ml_rank = sub.add_parser("ml-rank", help="train the synthetic alert-priority model and rank fired alerts")
    ml_rank.add_argument("--detections", default="detections")
    ml_rank.add_argument("--events", default="data/telemetry.jsonl")
    ml_rank.add_argument("--output")
    ml_rank.set_defaults(func=cmd_ml_rank)

    coverage = sub.add_parser("coverage")
    coverage.add_argument("--detections", default="detections")
    coverage.set_defaults(func=cmd_coverage)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
