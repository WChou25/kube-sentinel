import json
import subprocess
import sys
from pathlib import Path

from loader import load_yaml_documents
from parser import build_cluster_state
from rules import evaluate_rules


EXPECTED = {
    "safe_case": {
        "expected_attack_paths": 0,
        "should_flag": [],
        "should_not_flag": ["attack path", "privileged", "host"],
    },
    "risky_case": {
        "expected_attack_paths": 1,
        "should_flag": ["attack path", "privileged", "missing networkpolicy"],
        "should_not_flag": [],
    },
    "hostpath_case": {
        "expected_attack_paths": 1,
        "should_flag": ["attack path", "host-level access"],
        "should_not_flag": ["privileged workload detected"],
    },
    "hostnetwork_case": {
        "expected_attack_paths": 1,
        "should_flag": ["attack path", "host-level access", "dangerous linux capabilities"],
        "should_not_flag": [],
    },
    "segmented_case": {
        "expected_attack_paths": 0,
        "should_flag": ["privileged"],
        "should_not_flag": ["attack path"],
    },
    "wildcard_ipblock_case": {
        "expected_attack_paths": 0,
        "should_flag": ["privileged", "external exposure"],
        "should_not_flag": ["attack path"],
    },
    "orphan_service_case": {
        "expected_attack_paths": 0,
        "should_flag": ["privileged", "external exposure"],
        "should_not_flag": ["attack path", "missing networkpolicy"],
    },
    "ingress_case": {
        "expected_attack_paths": 1,
        "should_flag": ["attack path", "privileged", "external exposure via ingress"],
        "should_not_flag": [],
    },
    "hardening_case": {
        "expected_attack_paths": 0,
        "should_flag": ["allowprivilegeescalation", "runasnonroot", "missing cpu/memory limits"],
        "should_not_flag": ["attack path", "privileged workload detected"],
    },
    "multihop_case": {
        "expected_attack_paths": 1,
        "should_flag": ["multi-hop", "privileged", "attack path"],
        "should_not_flag": [],
    },
}


def _findings_text(findings):
    return " | ".join(
        (f["title"] + " " + f["details"]).lower() for f in findings
    )


def run_kube_sentinel(case_path):
    objects = load_yaml_documents(case_path)
    state = build_cluster_state(objects)
    return evaluate_rules(state)


def _checkov_available():
    try:
        result = subprocess.run(
            [sys.executable, "-m", "checkov.main", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def run_checkov(case_path):
    if not _checkov_available():
        return None
    try:
        result = subprocess.run(
            [sys.executable, "-m", "checkov.main", "--quiet", "-o", "json", "-f", str(case_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    try:
        data = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None
    if isinstance(data, list):
        data = data[0] if data else {}
    failed = data.get("results", {}).get("failed_checks", [])
    passed = data.get("results", {}).get("passed_checks", [])
    return {"failed": len(failed), "passed": len(passed)}


def run_kubescape(case_path):
    try:
        subprocess.run(
            ["kubescape", "version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.CalledProcessError, FileNotFoundError):
        return None

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name
    try:
        subprocess.run(
            ["kubescape", "scan", "--format", "json", "--output", output_path, str(case_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        with open(output_path) as handle:
            data = json.load(handle)
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        return None
    finally:
        try:
            Path(output_path).unlink()
        except OSError:
            pass

    summary = data.get("summaryDetails", {})
    controls = summary.get("controls", {}) or {}
    failed = sum(
        1
        for c in controls.values()
        if str(c.get("status", "")).lower() in {"failed", "failing"}
    )
    return {"failed": failed, "total": len(controls)}


def score_kube_sentinel(findings, expected):
    text = _findings_text(findings)
    path_count = sum(1 for f in findings if "attack path" in f["title"].lower())

    tp = sum(1 for kw in expected["should_flag"] if kw.lower() in text)
    fn = len(expected["should_flag"]) - tp
    fp = sum(1 for kw in expected["should_not_flag"] if kw.lower() in text)

    path_delta = path_count - expected["expected_attack_paths"]
    return {
        "path_count": path_count,
        "expected_paths": expected["expected_attack_paths"],
        "path_delta": path_delta,
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def main():
    project_root = Path(__file__).resolve().parent.parent
    cases_dir = project_root / "cases"

    rows = []
    totals = {"tp": 0, "fp": 0, "fn": 0, "path_correct": 0, "cases": 0}

    for stem, expected in EXPECTED.items():
        case_path = cases_dir / f"{stem}.yaml"
        if not case_path.exists():
            continue
        findings = run_kube_sentinel(case_path)
        ks_score = score_kube_sentinel(findings, expected)
        checkov = run_checkov(case_path)
        kubescape = run_kubescape(case_path)
        rows.append((stem, ks_score, checkov, kubescape))

        totals["tp"] += ks_score["tp"]
        totals["fp"] += ks_score["fp"]
        totals["fn"] += ks_score["fn"]
        totals["cases"] += 1
        if ks_score["path_delta"] == 0:
            totals["path_correct"] += 1

    print("# Kube-Sentinel Benchmark\n")
    print("| Case | Paths (found/expected) | TP | FP | FN | Checkov | Kubescape |")
    print("|---|---|---|---|---|---|---|")
    for stem, ks, ck, kss in rows:
        ck_str = "not installed" if ck is None else f"{ck['failed']} failed"
        kss_str = "not installed" if kss is None else f"{kss['failed']}/{kss['total']} failed"
        print(
            f"| {stem} | {ks['path_count']}/{ks['expected_paths']} "
            f"| {ks['tp']} | {ks['fp']} | {ks['fn']} | {ck_str} | {kss_str} |"
        )

    print(
        f"\n**Totals across {totals['cases']} cases:** "
        f"TP={totals['tp']}, FP={totals['fp']}, FN={totals['fn']}, "
        f"attack-path count correct on {totals['path_correct']}/{totals['cases']} cases."
    )

    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if (totals["tp"] + totals["fp"]) else 1.0
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if (totals["tp"] + totals["fn"]) else 1.0
    print(f"Precision: {precision:.2f} | Recall: {recall:.2f}")

    if totals["fp"] == 0 and totals["fn"] == 0:
        sys.exit(0)
    sys.exit(0)


if __name__ == "__main__":
    main()
