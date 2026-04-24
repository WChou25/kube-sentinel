def parse_service(obj):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {})
    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "type": spec.get("type", "ClusterIP"),
        "selector": spec.get("selector", {}) or {},
    }


def _collect_capabilities(containers):
    added = set()
    for container in containers:
        caps = container.get("securityContext", {}).get("capabilities", {}) or {}
        for cap in caps.get("add", []) or []:
            added.add(cap)
    return sorted(added)


def _collect_host_paths(volumes):
    paths = []
    for volume in volumes or []:
        host_path = volume.get("hostPath")
        if host_path and host_path.get("path"):
            paths.append(host_path["path"])
    return paths


def parse_deployment(obj):
    metadata = obj.get("metadata", {})
    template = obj.get("spec", {}).get("template", {})
    pod_metadata = template.get("metadata", {})
    pod_spec = template.get("spec", {})
    containers = pod_spec.get("containers", []) or []

    privileged = any(
        container.get("securityContext", {}).get("privileged", False)
        for container in containers
    )

    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "labels": pod_metadata.get("labels", {}) or {},
        "privileged": privileged,
        "host_network": bool(pod_spec.get("hostNetwork", False)),
        "host_pid": bool(pod_spec.get("hostPID", False)),
        "host_paths": _collect_host_paths(pod_spec.get("volumes", [])),
        "capabilities": _collect_capabilities(containers),
        "service_account": pod_spec.get("serviceAccountName")
        or pod_spec.get("serviceAccount", "default"),
    }


def _infer_policy_types(spec):
    declared = spec.get("policyTypes")
    if declared:
        return list(declared)
    inferred = []
    if spec.get("ingress") is not None:
        inferred.append("Ingress")
    if spec.get("egress") is not None:
        inferred.append("Egress")
    return inferred or ["Ingress"]


def parse_network_policy(obj):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {}) or {}
    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "pod_selector": (spec.get("podSelector", {}) or {}).get("matchLabels", {})
        or {},
        "policy_types": _infer_policy_types(spec),
        "ingress": spec.get("ingress", []) or [],
        "egress": spec.get("egress", []) or [],
    }


def build_cluster_state(objects):
    cluster_state = {
        "services": [],
        "deployments": [],
        "network_policies": [],
    }

    for obj in objects:
        kind = obj.get("kind")
        if kind == "Service":
            cluster_state["services"].append(parse_service(obj))
        elif kind == "Deployment":
            cluster_state["deployments"].append(parse_deployment(obj))
        elif kind == "NetworkPolicy":
            cluster_state["network_policies"].append(parse_network_policy(obj))

    return cluster_state
