from pathlib import Path
import unittest

from detectionforge.compiler import compile_kql
from detectionforge.rules import load_rules, rule_matches

ROOT = Path(__file__).resolve().parents[1]


class RuleTests(unittest.TestCase):
    def test_all_rules_validate_and_have_attack_mapping(self):
        rules = load_rules(ROOT / "detections")
        self.assertEqual(len(rules), 3)
        self.assertTrue(all(rule.attack_techniques for rule in rules))

    def test_kql_compiler_preserves_detection_logic(self):
        rule = [r for r in load_rules(ROOT / "detections") if r.id == "df-entra-001"][0]
        kql = compile_kql(rule)
        self.assertIn(rule.id, kql)
        self.assertIn("| where", kql)
        self.assertIn("AuditLogs", kql)

    def test_sigma_like_matcher_handles_modifiers(self):
        rule = [r for r in load_rules(ROOT / "detections") if r.id == "df-endpoint-001"][0]
        fields = {
            "FileName": "powershell.exe",
            "ProcessCommandLine": "powershell.exe -enc AAA Invoke-WebRequest https://example.invalid"
        }
        self.assertTrue(rule_matches(rule, fields))


if __name__ == "__main__":
    unittest.main()
