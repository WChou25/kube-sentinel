from collections import deque

from graph import (
    blocking_policies,
    can_pod_reach,
    exposed_entry_points,
    is_externally_exposed,
    service_targets,  # noqa: F401 (kept for external callers)
)

MAX_PATH_DEPTH = 4


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


def _check_exposure(cluster_state):
    findings = []
    services = cluster_state.get("services", [])
    ingresses = cluster_state.get("ingresses", []) or []

    ingress_targets = set()
    for ingress in ingresses:
        ns = ingress.get("namespace", "default")
        for backend in ingress.get("backends", []) or []:
            name = backend.get("service_name")
            if name:
                ingress_targets.add((ns, name))

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
        elif (service["namespace"], service["name"]) in ingress_targets:
            findings.append(
                _finding(
                    "medium",
                    "External exposure via Ingress",
                    f"Service {service['name']} is exposed externally through an Ingress.",
                )
            )

    for ingress in ingresses:
        if not ingress.get("backends"):
            continue
        findings.append(
            _finding(
                "low",
                "Ingress routes external traffic",
                f"Ingress {ingress['name']} routes external traffic to "
                f"{len(ingress['backends'])} backend(s).",
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


def _check_runtime_hardening(deployments):
    findings = []
    for deployment in deployments:
        name = deployment["name"]
        kind = deployment.get("kind", "Deployment")

        if deployment.get("allow_privilege_escalation"):
            findings.append(
                _finding(
                    "medium",
                    "allowPrivilegeEscalation not disabled",
                    f"{kind} {name} has containers that allow privilege escalation "
                    "(securityContext.allowPrivilegeEscalation is not false).",
                )
            )
        if not deployment.get("run_as_non_root"):
            findings.append(
                _finding(
                    "medium",
                    "runAsNonRoot not enforced",
                    f"{kind} {name} does not explicitly enforce runAsNonRoot; "
                    "containers may run as UID 0.",
                )
            )
        if deployment.get("read_write_root_fs"):
            findings.append(
                _finding(
                    "low",
                    "Writable root filesystem",
                    f"{kind} {name} has containers without readOnlyRootFilesystem=true.",
                )
            )
        if deployment.get("automount_sa_token") and deployment.get("service_account") == "default":
            findings.append(
                _finding(
                    "low",
                    "Default ServiceAccount token automount",
                    f"{kind} {name} uses the default ServiceAccount with "
                    "automountServiceAccountToken enabled.",
                )
            )
        if deployment.get("missing_resource_limits"):
            findings.append(
                _finding(
                    "low",
                    "Missing CPU/memory limits",
                    f"{kind} {name} has containers without both CPU and memory limits.",
                )
            )
    return findings


def _attack_paths(cluster_state):
    deployments = cluster_state.get("deployments", [])
    policies = cluster_state.get("network_policies", [])
    findings = []
    seen = set()
    blocked_seen = set()

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

        shortest_path = {frontend["name"]: [frontend]}
        queue = deque([frontend])

        while queue:
            current = queue.popleft()
            current_path = shortest_path[current["name"]]
            if len(current_path) >= MAX_PATH_DEPTH:
                continue

            for peer in deployments:
                if peer["name"] == current["name"]:
                    continue
                if peer["namespace"] != current["namespace"]:
                    continue
                if peer["name"] in shortest_path:
                    continue
                if not can_pod_reach(current, peer, policies):
                    blockers = blocking_policies(current, peer, policies)
                    if blockers and _is_risky_workload(peer):
                        blocked_key = (
                            "blocked",
                            service["name"],
                            current["name"],
                            peer["name"],
                        )
                        if blocked_key not in blocked_seen:
                            blocked_seen.add(blocked_key)
                            names = ", ".join(p["name"] for p in blockers)
                            findings.append(
                                _finding(
                                    "low",
                                    "Blocked pivot (segmentation working)",
                                    f"Attacker on {current['name']} cannot reach "
                                    f"{peer['name']}; blocked by NetworkPolicy: {names}.",
                                    score=0,
                                )
                            )
                    continue

                shortest_path[peer["name"]] = current_path + [peer]
                queue.append(peer)

                if _is_risky_workload(peer):
                    hop_count = len(shortest_path[peer["name"]]) - 1
                    hop_label = f"{hop_count} hop{'s' if hop_count != 1 else ''}"
                    tags = ", ".join(_workload_risk_tags(peer))
                    chain_names = [p["name"] for p in shortest_path[peer["name"]]]
                    key = ("pivot", service["name"], tuple(chain_names))
                    if key in seen:
                        continue
                    seen.add(key)
                    path_score = (
                        SEVERITY_WEIGHT["high"]
                        + _workload_score(peer)
                        - max(0, hop_count - 1)
                    )
                    chain_description = " -> ".join(chain_names)
                    findings.append(
                        _finding(
                            "high",
                            f"Attack Path: multi-hop pivot ({hop_label})",
                            f"Attacker enters via {service['name']}, chains "
                            f"through {chain_description} to reach {peer['name']} "
                            f"({tags}). No NetworkPolicy on any hop blocks the chain.",
                            path=["Internet", service["name"]] + chain_names,
                            score=path_score,
                        )
                    )

    return findings


def evaluate_rules(cluster_state):
    services = cluster_state.get("services", [])
    deployments = cluster_state.get("deployments", [])
    network_policies = cluster_state.get("network_policies", [])

    findings = []
    findings.extend(_check_exposure(cluster_state))
    findings.extend(_check_privileged(deployments))
    findings.extend(_check_host_access(deployments))
    findings.extend(_check_dangerous_capabilities(deployments))
    findings.extend(_check_segmentation(network_policies))
    findings.extend(_check_runtime_hardening(deployments))
    findings.extend(_attack_paths(cluster_state))

    findings.sort(
        key=lambda f: (
            0 if f["title"].startswith("Attack Path") else 1,
            -f.get("score", 0),
        )
    )
    return findings
