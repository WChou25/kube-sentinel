def _is_externally_exposed(service):
    return service.get("type") in {"LoadBalancer", "NodePort"}


def _selector_matches_labels(selector, labels):
    if not selector:
        return False
    return all(labels.get(key) == value for key, value in selector.items())


def evaluate_rules(cluster_state):
    findings = []
    services = cluster_state.get("services", [])
    deployments = cluster_state.get("deployments", [])
    network_policies = cluster_state.get("network_policies", [])

    for service in services:
        if _is_externally_exposed(service):
            findings.append(
                {
                    "severity": "medium",
                    "title": "External exposure detected",
                    "details": (
                        f"Service {service['name']} is exposed externally via "
                        f"{service['type']}."
                    ),
                }
            )

    for deployment in deployments:
        if deployment.get("privileged"):
            findings.append(
                {
                    "severity": "high",
                    "title": "Privileged workload detected",
                    "details": (
                        f"Deployment {deployment['name']} allows privileged containers."
                    ),
                }
            )

    if not network_policies:
        findings.append(
            {
                "severity": "medium",
                "title": "Missing NetworkPolicy",
                "details": "No NetworkPolicy resources were found in the cluster state.",
            }
        )

    has_network_policy = bool(network_policies)
    for service in services:
        if not _is_externally_exposed(service):
            continue

        frontend = next(
            (
                deployment
                for deployment in deployments
                if deployment["namespace"] == service["namespace"]
                and _selector_matches_labels(
                    service.get("selector", {}), deployment.get("labels", {})
                )
            ),
            None,
        )
        if not frontend:
            continue

        privileged_peer = next(
            (
                deployment
                for deployment in deployments
                if deployment["namespace"] == service["namespace"]
                and deployment["name"] != frontend["name"]
                and deployment.get("privileged")
            ),
            None,
        )
        if privileged_peer and not has_network_policy:
            findings.append(
                {
                    "severity": "high",
                    "title": "Attack Path Detected",
                    "details": (
                        "Internet -> "
                        f"{service['name']} -> {frontend['name']} -> "
                        f"{privileged_peer['name']}"
                    ),
                }
            )
            break

    return findings
