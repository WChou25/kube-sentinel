def generate_explanation(cluster_state, findings):
    if not findings:
        return (
            "This configuration appears low risk. The manifests do not show "
            "external exposure, privileged workloads, or obvious missing network "
            "segmentation in this simplified analysis."
        )

    services = cluster_state.get("services", [])
    deployments = cluster_state.get("deployments", [])
    network_policies = cluster_state.get("network_policies", [])

    exposed_service = next(
        (
            service
            for service in services
            if service.get("type") in {"LoadBalancer", "NodePort"}
        ),
        None,
    )
    privileged_deployment = next(
        (deployment for deployment in deployments if deployment.get("privileged")),
        None,
    )

    sentences = []
    attack_path_present = any(
        finding.get("title") == "Attack Path Detected" for finding in findings
    )

    if attack_path_present:
        sentences.append("This configuration presents a high-risk attack path.")
    else:
        sentences.append("This configuration shows some security-relevant conditions.")

    if exposed_service:
        sentences.append(
            f"The {exposed_service['name']} service is externally exposed via "
            f"{exposed_service['type']}, providing an entry point."
        )

    if not network_policies:
        sentences.append(
            "Because no NetworkPolicies restrict communication, pods may be able "
            "to reach internal workloads more freely."
        )

    if privileged_deployment:
        sentences.append(
            f"The {privileged_deployment['name']} deployment runs privileged "
            "containers, which increases the impact of compromise."
        )

    if not exposed_service and network_policies and not privileged_deployment:
        sentences.append(
            "In this demo, the configuration looks comparatively safer because "
            "it avoids the main risky signals being checked."
        )

    return " ".join(sentences)
