"""Block publication when scanner JSON reports exceed the configured thresholds."""

import argparse
import json
from collections import Counter
from pathlib import Path


THRESHOLDS = {
    "semgrep": {"ERROR"},
    "trivy": {"HIGH", "CRITICAL"},
    "zap": {"HIGH"},
}


def object_value(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def list_value(value, field, nullable=False):
    if value is None and nullable:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array")
    return value


def severity_value(value, allowed):
    if not isinstance(value, str) or value.upper() not in allowed:
        raise ValueError(f"Unknown or missing severity: {value!r}")
    return value.upper()


def semgrep_findings(report):
    for error in list_value(report.get("errors", []), "errors"):
        error = object_value(error, "errors[]")
        if str(error.get("level", "error")).lower() == "error":
            raise ValueError(f"Semgrep scan error: {error.get('message', error.get('type', 'unknown'))}")
    for result in list_value(report["results"], "results"):
        result = object_value(result, "results[]")
        extra = object_value(result["extra"], "results[].extra")
        severity = severity_value(extra.get("severity"), {"ERROR", "WARNING", "INFO"})
        yield {
            "severity": severity,
            "id": result.get("check_id", "unknown"),
            "location": result.get("path", "unknown"),
            "message": extra.get("message", ""),
        }


def trivy_findings(report):
    if report.get("SchemaVersion") != 2:
        raise ValueError("Expected Trivy SchemaVersion 2")
    # Trivy omits Results and Vulnerabilities when their arrays are empty.
    for result in list_value(report.get("Results", []), "Results", nullable=True):
        result = object_value(result, "Results[]")
        for vulnerability in list_value(
            result.get("Vulnerabilities", []), "Vulnerabilities", nullable=True
        ):
            vulnerability = object_value(vulnerability, "Vulnerabilities[]")
            severity = severity_value(
                vulnerability.get("Severity"), {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            )
            yield {
                "severity": severity,
                "id": vulnerability.get("VulnerabilityID", "unknown"),
                "location": result.get("Target", "unknown"),
                "message": vulnerability.get("PkgName", ""),
            }


def zap_findings(report):
    risks = {"0": "INFORMATIONAL", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
    for site in list_value(report["site"], "site"):
        site = object_value(site, "site[]")
        for alert in list_value(site["alerts"], "site[].alerts"):
            alert = object_value(alert, "alerts[]")
            code = str(alert.get("riskcode"))
            if code not in risks:
                raise ValueError(f"Unknown or missing ZAP riskcode: {code!r}")
            yield {
                "severity": risks[code],
                "id": alert.get("pluginid", "unknown"),
                "location": site.get("@name", "unknown"),
                "message": alert.get("name", alert.get("alert", "")),
            }


PARSERS = {"semgrep": semgrep_findings, "trivy": trivy_findings, "zap": zap_findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for scanner in PARSERS:
        parser.add_argument(f"--{scanner}", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args(argv)
    summary = {
        "status": "passed",
        "thresholds": {scanner: sorted(levels) for scanner, levels in THRESHOLDS.items()},
        "reports": {},
        "errors": [],
    }
    blocked = 0
    for scanner, parse_findings in PARSERS.items():
        path = getattr(args, scanner)
        try:
            report = object_value(json.loads(path.read_text(encoding="utf-8")), str(path))
            findings = list(parse_findings(report))
            blocking = [finding for finding in findings if finding["severity"] in THRESHOLDS[scanner]]
            counts = dict(Counter(finding["severity"] for finding in findings))
            summary["reports"][scanner] = {
                "path": str(path), "counts": counts, "blocking_findings": blocking
            }
            blocked += len(blocking)
            print(f"{scanner}: findings={len(findings)}, blocking={len(blocking)}, severities={counts}")
            for finding in blocking[:20]:
                print(f"  {finding['severity']} {finding['id']} {finding['location']}: {finding['message']}")
            if len(blocking) > 20:
                print(f"  See summary for {len(blocking) - 20} more blocking findings")
        except (OSError, ValueError, KeyError) as exc:
            error = {"scanner": scanner, "path": str(path), "message": str(exc)}
            summary["errors"].append(error)
            print(f"{scanner}: invalid report {path}: {exc}")

    exit_code = 2 if summary["errors"] else 1 if blocked else 0
    summary["status"] = "failed" if exit_code else "passed"
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Security gate {summary['status']}: {blocked} blocking findings, {len(summary['errors'])} report errors")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
