from pathlib import Path
import unittest

from detectionforge.coverage import attack_coverage
from detectionforge.feedback import summarize_feedback
from detectionforge.replay import evaluate_rule, load_events
from detectionforge.rules import load_rules

ROOT = Path(__file__).resolve().parents[1]


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(ROOT / "detections")
        cls.events = load_events(ROOT / "data" / "telemetry.jsonl")

    def test_all_baseline_rules_pass_quality_gate(self):
        runs = [evaluate_rule(rule, self.events) for rule in self.rules]
        self.assertTrue(all(run.gate_passed for run in runs), runs)
        self.assertTrue(all(run.precision >= 0.80 for run in runs))
        self.assertTrue(all(run.recall >= 0.80 for run in runs))
        self.assertTrue(all(run.false_positive_rate <= 0.10 for run in runs))

    def test_attack_coverage_contains_expected_techniques(self):
        coverage = attack_coverage(self.rules)
        self.assertIn("T1098.003", coverage)
        self.assertIn("T1059.001", coverage)
        self.assertIn("T1078", coverage)

    def test_analyst_feedback_summary(self):
        summary = summarize_feedback(ROOT / "data" / "analyst_feedback.json", "df-entra-001")
        self.assertEqual(summary.reviewed, 2)
        self.assertEqual(summary.analyst_precision, 0.5)
        self.assertEqual(summary.common_benign_reasons[0][0], "approved security test")


if __name__ == "__main__":
    unittest.main()
