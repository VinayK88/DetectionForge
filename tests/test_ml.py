import unittest

from detectionforge.ml import FEATURE_NAMES, active_learning_candidates, ml_report, rank_events
from detectionforge.replay import load_events
from detectionforge.rules import load_rules


class AlertMLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events("data/telemetry.jsonl")
        cls.rules = load_rules("detections")

    def test_ml_report_has_bounded_metrics(self):
        report = ml_report(self.events, self.rules)
        metrics = report["model"]
        self.assertGreater(metrics["test_samples"], 0)
        for name in ("precision", "recall", "f1", "roc_auc"):
            self.assertGreaterEqual(metrics[name], 0.0)
            self.assertLessEqual(metrics[name], 1.0)

    def test_labels_are_not_model_features(self):
        lowered = {name.lower() for name in FEATURE_NAMES}
        self.assertNotIn("malicious", lowered)
        self.assertNotIn("scenario", lowered)

    def test_ranker_only_returns_fired_alerts(self):
        rows = rank_events(self.events, self.rules)
        self.assertTrue(rows)
        self.assertTrue(all(row.rule_match_count > 0 for row in rows))
        self.assertTrue(all(0.0 <= row.probability <= 1.0 for row in rows))

    def test_active_learning_prioritizes_uncertainty(self):
        rows = active_learning_candidates(self.events, self.rules, limit=5)
        self.assertLessEqual(len(rows), 5)
        uncertainty = [row.uncertainty for row in rows]
        self.assertEqual(uncertainty, sorted(uncertainty, reverse=True))


if __name__ == "__main__":
    unittest.main()
