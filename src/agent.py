def _attack_path_findings(findings):
    return [f for f in findings if f.get("title", "").startswith("Attack Path")]


def _severity_counts(findings):
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "low")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def generate_explanation(cluster_state, findings):
    if not findings:
        return (
            "This configuration appears low risk. No external exposure, privileged "
            "workloads, host-level access, or missing segmentation were detected."
        )

    counts = _severity_counts(findings)
    paths = _attack_path_findings(findings)
    sentences = []

    if paths:
        sentences.append(
            f"This configuration presents {len(paths)} attack path(s) reachable "
            "from the internet."
        )
        for path_finding in paths:
            path = path_finding.get("path")
            if path:
                sentences.append("Path: " + " -> ".join(path) + ".")
        sentences.append(
            "The chain connects an externally exposed service to a workload with "
            "elevated privileges or host access, so an initial compromise at the "
            "entry point can escalate toward the node or internal targets."
        )
    else:
        sentences.append(
            "This configuration shows security-relevant conditions but no complete "
            "internet-to-privilege attack path was assembled."
        )

    deployments = cluster_state.get("deployments", [])
    privileged = [d for d in deployments if d.get("privileged")]
    host_access = [
        d
        for d in deployments
        if d.get("host_network") or d.get("host_pid") or d.get("host_paths")
    ]
    if privileged:
        names = ", ".join(d["name"] for d in privileged)
        sentences.append(f"Privileged workloads: {names}.")
    if host_access:
        names = ", ".join(d["name"] for d in host_access)
        sentences.append(
            f"Workloads with host-level access (hostNetwork/hostPID/hostPath): "
            f"{names}."
        )

    if not cluster_state.get("network_policies"):
        sentences.append(
            "No NetworkPolicies are defined, so lateral movement between pods is "
            "unrestricted by default."
        )

    sentences.append(
        f"Finding counts - high: {counts.get('high', 0)}, "
        f"medium: {counts.get('medium', 0)}, low: {counts.get('low', 0)}."
    )

    return " ".join(sentences)
