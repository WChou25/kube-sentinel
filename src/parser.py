def parse_service(obj):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {})
    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "type": spec.get("type", "ClusterIP"),
        "selector": spec.get("selector", {}) or {},
    }


def parse_deployment(obj):
    metadata = obj.get("metadata", {})
    template = obj.get("spec", {}).get("template", {})
    pod_metadata = template.get("metadata", {})
    pod_spec = template.get("spec", {})
    containers = pod_spec.get("containers", [])

    privileged = any(
        container.get("securityContext", {}).get("privileged", False)
        for container in containers
    )

    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "labels": pod_metadata.get("labels", {}) or {},
        "privileged": privileged,
    }


def parse_network_policy(obj):
    metadata = obj.get("metadata", {})
    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
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
