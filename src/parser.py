POD_TEMPLATE_KINDS = {
    "Deployment": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
    "DaemonSet": ("spec", "template"),
    "ReplicaSet": ("spec", "template"),
    "Job": ("spec", "template"),
    "CronJob": ("spec", "jobTemplate", "spec", "template"),
    "Pod": None,
}


def _dig(obj, path):
    current = obj
    for key in path:
        current = (current or {}).get(key, {})
    return current or {}


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


def _any_allows_privilege_escalation(containers):
    for container in containers:
        value = container.get("securityContext", {}).get("allowPrivilegeEscalation")
        if value is None or value is True:
            return True
    return False


def _any_read_write_root_fs(containers):
    for container in containers:
        value = container.get("securityContext", {}).get("readOnlyRootFilesystem")
        if not value:
            return True
    return False


def _any_missing_resource_limits(containers):
    for container in containers:
        limits = (container.get("resources") or {}).get("limits") or {}
        if "cpu" not in limits or "memory" not in limits:
            return True
    return False


def _effective_run_as_non_root(pod_spec, containers):
    pod_level = (pod_spec.get("securityContext") or {}).get("runAsNonRoot")
    if pod_level is True:
        return True
    for container in containers:
        value = container.get("securityContext", {}).get("runAsNonRoot")
        if value is None or value is False:
            return False
    return True


def parse_workload(obj):
    kind = obj.get("kind", "Deployment")
    metadata = obj.get("metadata", {})
    template_path = POD_TEMPLATE_KINDS.get(kind)

    if template_path is None:
        pod_metadata = metadata
        pod_spec = obj.get("spec", {}) or {}
    else:
        template = _dig(obj, template_path)
        pod_metadata = template.get("metadata", {}) or {}
        pod_spec = template.get("spec", {}) or {}

    containers = pod_spec.get("containers", []) or []

    privileged = any(
        container.get("securityContext", {}).get("privileged", False)
        for container in containers
    )

    automount = pod_spec.get("automountServiceAccountToken")
    if automount is None:
        automount = True

    return {
        "kind": kind,
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "labels": pod_metadata.get("labels", {}) or metadata.get("labels", {}) or {},
        "privileged": privileged,
        "host_network": bool(pod_spec.get("hostNetwork", False)),
        "host_pid": bool(pod_spec.get("hostPID", False)),
        "host_paths": _collect_host_paths(pod_spec.get("volumes", [])),
        "capabilities": _collect_capabilities(containers),
        "service_account": pod_spec.get("serviceAccountName")
        or pod_spec.get("serviceAccount", "default"),
        "allow_privilege_escalation": _any_allows_privilege_escalation(containers),
        "run_as_non_root": _effective_run_as_non_root(pod_spec, containers),
        "read_write_root_fs": _any_read_write_root_fs(containers),
        "automount_sa_token": bool(automount),
        "missing_resource_limits": _any_missing_resource_limits(containers),
    }


def parse_deployment(obj):
    return parse_workload(obj)


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


def parse_ingress(obj):
    metadata = obj.get("metadata", {})
    spec = obj.get("spec", {}) or {}
    rules = spec.get("rules") or []

    backends = []
    for rule in rules:
        http = (rule or {}).get("http") or {}
        for path in http.get("paths", []) or []:
            backend = (path or {}).get("backend", {}) or {}
            service = backend.get("service") or {}
            service_name = service.get("name")
            if service_name:
                backends.append(
                    {
                        "service_name": service_name,
                        "host": rule.get("host"),
                        "path": path.get("path"),
                    }
                )

    default_backend = spec.get("defaultBackend") or {}
    default_service = (default_backend.get("service") or {}).get("name")
    if default_service:
        backends.append({"service_name": default_service, "host": None, "path": "/"})

    return {
        "name": metadata.get("name", "unknown"),
        "namespace": metadata.get("namespace", "default"),
        "backends": backends,
        "ingress_class": spec.get("ingressClassName")
        or metadata.get("annotations", {}).get("kubernetes.io/ingress.class"),
    }


def parse_service_account(obj):
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
        "ingresses": [],
        "service_accounts": [],
    }

    for obj in objects:
        kind = obj.get("kind")
        if kind == "Service":
            cluster_state["services"].append(parse_service(obj))
        elif kind in POD_TEMPLATE_KINDS:
            cluster_state["deployments"].append(parse_workload(obj))
        elif kind == "NetworkPolicy":
            cluster_state["network_policies"].append(parse_network_policy(obj))
        elif kind == "Ingress":
            cluster_state["ingresses"].append(parse_ingress(obj))
        elif kind == "ServiceAccount":
            cluster_state["service_accounts"].append(parse_service_account(obj))

    return cluster_state
