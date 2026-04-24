import hashlib
import json
from pathlib import Path


TOOL_VERSION = "0.2.0"


def _severity_to_level(severity):
    return {
        "high": "error",
        "medium": "warning",
        "low": "note",
    }.get(severity, "none")


def _rule_id(title):
    digest = hashlib.sha1(title.encode("utf-8")).hexdigest()[:6].upper()
    return f"KS-{digest}"


def build_sarif(findings, case_path):
    case_uri = Path(case_path).as_posix()

    rules_by_id = {}
    results = []

    for finding in findings:
        rule_id = _rule_id(finding["title"])
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": finding["title"].replace(" ", ""),
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["title"]},
                "defaultConfiguration": {"level": _severity_to_level(finding["severity"])},
                "properties": {"severity": finding["severity"]},
            }

        result = {
            "ruleId": rule_id,
            "level": _severity_to_level(finding["severity"]),
            "message": {"text": finding["details"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": case_uri},
                    }
                }
            ],
            "properties": {
                "severity": finding["severity"],
                "score": finding.get("score", 0),
            },
        }
        if finding.get("path"):
            result["properties"]["attackPath"] = finding["path"]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kube-sentinel",
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/WChou25/kube-sentinel",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(findings, case_path, output_path):
    payload = build_sarif(findings, case_path)
    Path(output_path).write_text(json.dumps(payload, indent=2))
    return output_path
