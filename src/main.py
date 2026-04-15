import sys
from pathlib import Path

from agent import generate_explanation
from loader import load_yaml_documents
from parser import build_cluster_state
from rules import evaluate_rules


CASE_FILES = {
    "safe": "safe_case.yaml",
    "risky": "risky_case.yaml",
}


def _format_cluster_summary(cluster_state):
    lines = []

    for service in cluster_state["services"]:
        lines.append(f"  - Service: {service['name']} ({service['type']})")

    for deployment in cluster_state["deployments"]:
        suffix = " [PRIVILEGED]" if deployment["privileged"] else ""
        lines.append(f"  - Deployment: {deployment['name']}{suffix}")

    lines.append(f"  - NetworkPolicies: {len(cluster_state['network_policies'])}")
    return "\n".join(lines)


def _format_findings(findings):
    if not findings:
        return "  [LOW] No findings detected"

    return "\n".join(
        f"  [{finding['severity'].upper()}] {finding['title']}\n"
        f"      {finding['details']}"
        for finding in findings
    )


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in CASE_FILES:
        print("Usage: python src/main.py [safe|risky]")
        sys.exit(1)

    case_name = sys.argv[1]
    project_root = Path(__file__).resolve().parent.parent
    case_path = project_root / "cases" / CASE_FILES[case_name]

    objects = load_yaml_documents(case_path)
    cluster_state = build_cluster_state(objects)
    findings = evaluate_rules(cluster_state)
    explanation = generate_explanation(cluster_state, findings)

    print(f"Loaded case: {case_path.name}\n")
    print("CLUSTER SUMMARY")
    print(_format_cluster_summary(cluster_state))
    print("\nFINDINGS")
    print(_format_findings(findings))
    print("\nAI ANALYSIS")
    print(explanation)


if __name__ == "__main__":
    main()
