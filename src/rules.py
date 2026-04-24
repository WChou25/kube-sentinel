from graph import (
    can_pod_reach,
    exposed_entry_points,
    is_externally_exposed,
    service_targets,
)


DANGEROUS_CAPABILITIES = {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "SYS_PTRACE", "ALL"}

SEVERITY_WEIGHT = {"high": 10, "medium": 5, "low": 1}


def _finding(severity, title, details, path=None, score=None):
    result = {"severity": severity, "title": title, "details": details}
    if path:
        result["path"] = path
    if score is not None:
        result["score"] = score
    else:
        result["score"] = SEVERITY_WEIGHT.get(severity, 1)
    return result


def _workload_score(deployment):
    score = 0
    if deployment.get("privileged"):
        score += 6
    if deployment.get("host_network"):
        score += 5
    if deployment.get("host_pid"):
        score += 4
    if deployment.get("host_paths"):
        score += 5
    score += len(set(deployment.get("capabilities", [])) & DANGEROUS_CAPABILITIES)
    return score


def _workload_risk_tags(deployment):
    tags = []
    if deployment.get("privileged"):
        tags.append("privileged containers")
    if deployment.get("host_network"):
        tags.append("hostNetwork")
    if deployment.get("host_pid"):
        tags.append("hostPID")
    if deployment.get("host_paths"):
        tags.append("hostPath mounts")
    dangerous = set(deployment.get("capabilities", [])) & DANGEROUS_CAPABILITIES
    if dangerous:
        tags.append(f"capabilities: {', '.join(sorted(dangerous))}")
    return tags


def _is_risky_workload(deployment):
    return bool(_workload_risk_tags(deployment))


def _check_exposure(services):
    findings = []
    for service in services:
        if is_externally_exposed(service):
            findings.append(
                _finding(
                    "medium",
                    "External exposure detected",
                    f"Service {service['name']} is exposed externally via "
                    f"{service['type']}.",
                )
            )
    return findings


def _check_privileged(deployments):
    findings = []
    for deployment in deployments:
        if deployment.get("privileged"):
            findings.append(
                _finding(
                    "high",
                    "Privileged workload detected",
                    f"Deployment {deployment['name']} allows privileged containers.",
                )
            )
    return findings


def _check_host_access(deployments):
    findings = []
    for deployment in deployments:
        reasons = []
        if deployment.get("host_network"):
            reasons.append("hostNetwork=true")
        if deployment.get("host_pid"):
            reasons.append("hostPID=true")
        if deployment.get("host_paths"):
            reasons.append(f"hostPath mounts {deployment['host_paths']}")
        if reasons:
            findings.append(
                _finding(
                    "high",
                    "Host-level access on workload",
                    f"Deployment {deployment['name']} exposes the node via "
                    + "; ".join(reasons)
                    + ".",
                )
            )
    return findings


def _check_dangerous_capabilities(deployments):
    findings = []
    for deployment in deployments:
        dangerous = set(deployment.get("capabilities", [])) & DANGEROUS_CAPABILITIES
        if dangerous:
            findings.append(
                _finding(
                    "medium",
                    "Dangerous Linux capabilities added",
                    f"Deployment {deployment['name']} adds capabilities "
                    f"{sorted(dangerous)}.",
                )
            )
    return findings


def _check_segmentation(network_policies):
    if network_policies:
        return []
    return [
        _finding(
            "medium",
            "Missing NetworkPolicy",
            "No NetworkPolicy resources were found in the cluster state.",
        )
    ]


def _attack_paths(cluster_state):
    deployments = cluster_state.get("deployments", [])
    policies = cluster_state.get("network_policies", [])
    findings = []
    seen = set()

    for service, frontend in exposed_entry_points(cluster_state):
        if _is_risky_workload(frontend):
            tags = ", ".join(_workload_risk_tags(frontend))
            key = ("direct", service["name"], frontend["name"])
            if key not in seen:
                seen.add(key)
                path_score = SEVERITY_WEIGHT["high"] + _workload_score(frontend) + 2
                findings.append(
                    _finding(
                        "high",
                        "Attack Path: direct risky exposure",
                        f"Exposed service {service['name']} targets workload "
                        f"{frontend['name']} which has {tags}.",
                        path=["Internet", service["name"], frontend["name"]],
                        score=path_score,
                    )
                )

        for peer in deployments:
            if peer["name"] == frontend["name"]:
                continue
            if peer["namespace"] != frontend["namespace"]:
                continue
            if not _is_risky_workload(peer):
                continue
            if not can_pod_reach(frontend, peer, policies):
                continue
            tags = ", ".join(_workload_risk_tags(peer))
            key = ("pivot", service["name"], frontend["name"], peer["name"])
            if key in seen:
                continue
            seen.add(key)
            path_score = SEVERITY_WEIGHT["high"] + _workload_score(peer)
            findings.append(
                _finding(
                    "high",
                    "Attack Path: pivot to risky peer",
                    f"From {frontend['name']}, an attacker can reach "
                    f"{peer['name']} ({tags}) with no segmentation blocking it.",
                    path=[
                        "Internet",
                        service["name"],
                        frontend["name"],
                        peer["name"],
                    ],
                    score=path_score,
                )
            )

    return findings


def evaluate_rules(cluster_state):
    services = cluster_state.get("services", [])
    deployments = cluster_state.get("deployments", [])
    network_policies = cluster_state.get("network_policies", [])

    findings = []
    findings.extend(_check_exposure(services))
    findings.extend(_check_privileged(deployments))
    findings.extend(_check_host_access(deployments))
    findings.extend(_check_dangerous_capabilities(deployments))
    findings.extend(_check_segmentation(network_policies))
    findings.extend(_attack_paths(cluster_state))

    findings.sort(
        key=lambda f: (
            0 if f["title"].startswith("Attack Path") else 1,
            -f.get("score", 0),
        )
    )
    return findings
