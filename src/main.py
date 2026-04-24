import argparse
import sys
from pathlib import Path

from agent import generate_explanation
from loader import load_yaml_documents
from parser import build_cluster_state
from rules import evaluate_rules


def _format_cluster_summary(cluster_state):
    lines = []

    for service in cluster_state["services"]:
        lines.append(f"  - Service: {service['name']} ({service['type']})")

    for deployment in cluster_state["deployments"]:
        tags = []
        if deployment.get("privileged"):
            tags.append("PRIVILEGED")
        if deployment.get("host_network"):
            tags.append("hostNetwork")
        if deployment.get("host_pid"):
            tags.append("hostPID")
        if deployment.get("host_paths"):
            tags.append("hostPath")
        if deployment.get("capabilities"):
            tags.append("caps:" + ",".join(deployment["capabilities"]))
        suffix = f" [{' '.join(tags)}]" if tags else ""
        lines.append(f"  - Deployment: {deployment['name']}{suffix}")

    lines.append(f"  - NetworkPolicies: {len(cluster_state['network_policies'])}")
    return "\n".join(lines)


def _format_findings(findings):
    if not findings:
        return "  [LOW] No findings detected"

    blocks = []
    for finding in findings:
        score_tag = f" score={finding['score']}" if "score" in finding else ""
        header = (
            f"  [{finding['severity'].upper()}{score_tag}] {finding['title']}\n"
            f"      {finding['details']}"
        )
        if finding.get("path"):
            header += "\n      Path: " + " -> ".join(finding["path"])
        blocks.append(header)
    return "\n".join(blocks)


def _resolve_case_path(arg, project_root):
    cases_dir = project_root / "cases"
    direct = Path(arg)
    if direct.exists():
        return direct
    candidates = [
        cases_dir / f"{arg}.yaml",
        cases_dir / f"{arg}_case.yaml",
        cases_dir / arg,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _list_cases(project_root):
    cases_dir = project_root / "cases"
    if not cases_dir.exists():
        return []
    return sorted(p.stem for p in cases_dir.glob("*.yaml"))


def main():
    project_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(description="Kube-Sentinel: Kubernetes misconfig analyzer")
    parser.add_argument("case", help="Case name (e.g. 'risky') or path to a YAML file")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Use the Claude LLM agent for explanation (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--sarif",
        metavar="PATH",
        help="Write findings as SARIF 2.1.0 to PATH (for CI code scanning)",
    )
    args = parser.parse_args()

    case_path = _resolve_case_path(args.case, project_root)
    if case_path is None:
        available = _list_cases(project_root)
        if available:
            print("Available cases: " + ", ".join(available))
        sys.exit(1)

    objects = load_yaml_documents(case_path)
    cluster_state = build_cluster_state(objects)
    findings = evaluate_rules(cluster_state)

    if args.sarif:
        from sarif import write_sarif

        write_sarif(findings, case_path, args.sarif)
        print(f"SARIF written to {args.sarif}")

    print(f"Loaded case: {case_path.name}\n")
    print("CLUSTER SUMMARY")
    print(_format_cluster_summary(cluster_state))
    print("\nFINDINGS")
    print(_format_findings(findings))

    explanation = None
    if args.llm:
        from llm_agent import generate_llm_explanation

        print("\nLLM AGENT ANALYSIS (Claude Opus 4.7 with tool use)")
        explanation = generate_llm_explanation(cluster_state, findings)
        if explanation is None:
            print("  [!] LLM agent unavailable (missing ANTHROPIC_API_KEY or SDK). "
                  "Falling back to simulated agent.")

    if explanation is None:
        print("\nAI ANALYSIS (simulated)")
        explanation = generate_explanation(cluster_state, findings)

    print(explanation)


if __name__ == "__main__":
    main()
