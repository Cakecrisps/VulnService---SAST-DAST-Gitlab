import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CHECKER = Path(__file__).resolve().parents[1] / "scripts" / "check_scan_reports.py"


class SecurityGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.reports = {
            "semgrep": {"results": [], "errors": []},
            "trivy": {"SchemaVersion": 2, "Results": []},
            "zap": {"site": []},
        }

    def run_gate(self, expected, overrides=None):
        args = [sys.executable, str(CHECKER)]
        for scanner, report in self.reports.items():
            path = self.root / f"{scanner}.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            args.extend([f"--{scanner}", str(path)])
        for scanner, content in (overrides or {}).items():
            path = self.root / f"{scanner}.json"
            if content is None:
                path.unlink()
            else:
                path.write_text(content, encoding="utf-8")
        summary_path = self.root / "results" / "summary.json"
        args.extend(["--summary", str(summary_path)])
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "failed" if expected else "passed")
        return summary

    def semgrep_result(self, severity):
        return {"check_id": "sql-injection", "path": "main.py", "extra": {"severity": severity}}

    def trivy_result(self, severity):
        return {"Target": "image", "Vulnerabilities": [{"VulnerabilityID": "CVE-TEST", "Severity": severity}]}

    def zap_site(self, code, confidence="1"):
        return {"@name": "http://app", "alerts": [{"pluginid": "40018", "riskcode": code, "confidence": confidence}]}

    def test_empty_reports_pass(self):
        self.run_gate(0)

    def test_lower_severities_pass(self):
        self.reports["semgrep"]["results"] = [self.semgrep_result(level) for level in ("WARNING", "INFO")]
        self.reports["trivy"]["Results"] = [self.trivy_result(level) for level in ("UNKNOWN", "LOW", "MEDIUM")]
        self.reports["zap"]["site"] = [self.zap_site(code, "3") for code in ("0", "1", "2")]
        self.run_gate(0)

    def test_semgrep_error_blocks(self):
        self.reports["semgrep"]["results"] = [self.semgrep_result("ERROR")]
        summary = self.run_gate(1)
        self.assertEqual(summary["reports"]["semgrep"]["blocking_findings"][0]["id"], "sql-injection")

    def test_trivy_high_and_critical_block(self):
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                self.reports["trivy"]["Results"] = [self.trivy_result(severity)]
                summary = self.run_gate(1)
                self.assertEqual(summary["reports"]["trivy"]["counts"], {severity: 1})

    def test_zap_high_blocks_even_with_low_confidence(self):
        for code in ("3", 3):
            with self.subTest(code=code):
                self.reports["zap"]["site"] = [self.zap_site(code, "1")]
                self.run_gate(1)

    def test_checks_all_nested_targets_and_sites(self):
        self.reports["semgrep"]["results"] = [self.semgrep_result("INFO"), self.semgrep_result("ERROR")]
        self.reports["trivy"]["Results"] = [self.trivy_result("LOW"), self.trivy_result("CRITICAL")]
        self.reports["zap"]["site"] = [self.zap_site("1"), self.zap_site("3")]
        summary = self.run_gate(1)
        self.assertEqual(sum(len(report["blocking_findings"]) for report in summary["reports"].values()), 3)

    def test_does_not_match_severity_words_in_messages(self):
        result = self.semgrep_result("WARNING")
        result["extra"]["message"] = "ERROR HIGH CRITICAL"
        self.reports["semgrep"]["results"] = [result]
        site = self.zap_site("1", "3")
        site["alerts"][0]["riskdesc"] = "Low (High)"
        self.reports["zap"]["site"] = [site]
        self.run_gate(0)

    def test_trivy_optional_empty_arrays_pass(self):
        for report in ({"SchemaVersion": 2}, {"SchemaVersion": 2, "Results": None}, {"SchemaVersion": 2, "Results": [{"Target": "image", "Vulnerabilities": None}]}):
            with self.subTest(report=report):
                self.reports["trivy"] = report
                self.run_gate(0)

    def test_missing_report_blocks(self):
        for scanner in self.reports:
            with self.subTest(scanner=scanner):
                summary = self.run_gate(2, {scanner: None})
                self.assertEqual(summary["errors"][0]["scanner"], scanner)

    def test_malformed_json_and_structure_block(self):
        for content in ("", "{", "[]", "{}", '{"results": {}}', '{"results": [null]}'):
            with self.subTest(content=content):
                self.run_gate(2, {"semgrep": content})

    def test_unknown_severity_blocks(self):
        self.reports["trivy"]["Results"] = [self.trivy_result("UNRECOGNIZED")]
        self.run_gate(2)

    def test_missing_zap_risk_blocks(self):
        site = self.zap_site("3")
        del site["alerts"][0]["riskcode"]
        self.reports["zap"]["site"] = [site]
        self.run_gate(2)

    def test_semgrep_scan_error_blocks(self):
        self.reports["semgrep"]["errors"] = [{"level": "error", "message": "could not parse source"}]
        self.run_gate(2)

    def test_bad_report_does_not_hide_other_findings(self):
        self.reports["trivy"]["Results"] = [self.trivy_result("HIGH")]
        self.reports["zap"]["site"] = [self.zap_site("3")]
        summary = self.run_gate(2, {"semgrep": "{"})
        self.assertEqual(len(summary["errors"]), 1)
        self.assertEqual(len(summary["reports"]), 2)
        self.assertTrue(all(report["blocking_findings"] for report in summary["reports"].values()))


if __name__ == "__main__":
    unittest.main()
