EXTERNAL_SERVICE_TYPES = {"LoadBalancer", "NodePort"}


def _labels_match(selector, labels):
    if not selector:
        return True
    return all(labels.get(key) == value for key, value in selector.items())


def service_targets(service, deployments):
    selector = service.get("selector", {})
    if not selector:
        return []
    return [
        deployment
        for deployment in deployments
        if deployment["namespace"] == service["namespace"]
        and _labels_match(selector, deployment.get("labels", {}))
    ]


def _policy_applies(policy, deployment, direction):
    if policy["namespace"] != deployment["namespace"]:
        return False
    if direction not in policy.get("policy_types", []):
        return False
    return _labels_match(policy.get("pod_selector", {}), deployment.get("labels", {}))


def _peer_matches_pod(peer, source):
    pod_selector = peer.get("podSelector")
    if pod_selector is None:
        return False
    selector_labels = (pod_selector or {}).get("matchLabels", {}) or {}
    return _labels_match(selector_labels, source.get("labels", {}))


def _peer_matches_external(peer):
    ip_block = peer.get("ipBlock")
    if not ip_block:
        return False
    return ip_block.get("cidr", "").startswith("0.0.0.0/")


def _rule_allows(rule, source, external):
    peers = rule.get("from") if source or external else rule.get("to")
    if peers is None:
        return True
    if peers == []:
        return True
    for peer in peers:
        if external and _peer_matches_external(peer):
            return True
        if source and _peer_matches_pod(peer, source):
            return True
    return False


def can_pod_reach(source, target, network_policies):
    applicable = [
        policy
        for policy in network_policies
        if _policy_applies(policy, target, "Ingress")
    ]
    if not applicable:
        return True
    for policy in applicable:
        for rule in policy.get("ingress", []) or []:
            if _rule_allows(rule, source=source, external=False):
                return True
    return False


def can_external_reach(target, network_policies):
    applicable = [
        policy
        for policy in network_policies
        if _policy_applies(policy, target, "Ingress")
    ]
    if not applicable:
        return True
    for policy in applicable:
        for rule in policy.get("ingress", []) or []:
            if _rule_allows(rule, source=None, external=True):
                return True
    return False


def is_externally_exposed(service):
    return service.get("type") in EXTERNAL_SERVICE_TYPES


def exposed_entry_points(cluster_state):
    services = cluster_state.get("services", [])
    deployments = cluster_state.get("deployments", [])
    policies = cluster_state.get("network_policies", [])

    entries = []
    for service in services:
        if not is_externally_exposed(service):
            continue
        for target in service_targets(service, deployments):
            if can_external_reach(target, policies):
                entries.append((service, target))
    return entries
