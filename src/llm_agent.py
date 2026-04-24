import json
import os

from graph import can_external_reach, can_pod_reach


SYSTEM_PROMPT = (
    "You are Kube-Sentinel, a Kubernetes security analyst focused on network-critical "
    "misconfigurations and multi-step attack paths. You have tools to inspect the "
    "cluster state and to check reachability between workloads while honoring "
    "NetworkPolicies. Your job is to verify the rule-engine findings, trace complete "
    "Internet -> service -> workload -> escalation chains, and decide whether a "
    "finding represents a real attack path or is blocked by segmentation.\n\n"
    "Rules:\n"
    "- Do not invent findings the tools do not support.\n"
    "- Always call the reachability tools before claiming a path exists.\n"
    "- If a NetworkPolicy blocks an otherwise-risky peer, call that out explicitly.\n"
    "- Produce 2-4 short paragraphs: attack path summary, supporting evidence from "
    "your tool calls, and an overall risk rating (LOW/MEDIUM/HIGH)."
)


def _build_tools(cluster_state):
    try:
        from anthropic import beta_tool
    except ImportError as exc:
        raise RuntimeError(
            "anthropic SDK not installed. Run: pip install -r requirements.txt"
        ) from exc

    services = cluster_state["services"]
    deployments = cluster_state["deployments"]
    policies = cluster_state["network_policies"]

    def _find_deployment(name):
        return next((d for d in deployments if d["name"] == name), None)

    @beta_tool
    def list_services() -> str:
        """List all Kubernetes Services with their exposure type and selector."""
        return json.dumps(
            [
                {
                    "name": s["name"],
                    "namespace": s["namespace"],
                    "type": s["type"],
                    "selector": s["selector"],
                }
                for s in services
            ],
            indent=2,
        )

    @beta_tool
    def list_deployments() -> str:
        """List Deployments with security-relevant fields: privileged, hostNetwork, hostPID, hostPath mounts, added capabilities, labels."""
        return json.dumps(
            [
                {
                    "name": d["name"],
                    "namespace": d["namespace"],
                    "labels": d["labels"],
                    "privileged": d["privileged"],
                    "host_network": d["host_network"],
                    "host_pid": d["host_pid"],
                    "host_paths": d["host_paths"],
                    "capabilities": d["capabilities"],
                    "service_account": d["service_account"],
                }
                for d in deployments
            ],
            indent=2,
        )

    @beta_tool
    def list_network_policies() -> str:
        """List NetworkPolicies with podSelector, policyTypes, ingress rules, and egress rules."""
        return json.dumps(policies, indent=2)

    @beta_tool
    def check_pod_reachability(source_deployment: str, target_deployment: str) -> str:
        """Check whether pods from source_deployment can reach target_deployment over the pod network, honoring NetworkPolicies.

        Args:
            source_deployment: Name of the source Deployment.
            target_deployment: Name of the target Deployment.
        """
        source = _find_deployment(source_deployment)
        target = _find_deployment(target_deployment)
        if not source or not target:
            return f"Error: deployment not found (source={source_deployment}, target={target_deployment})"
        allowed = can_pod_reach(source, target, policies)
        verdict = "ALLOWED" if allowed else "BLOCKED_BY_NETWORK_POLICY"
        return f"{verdict}: {source_deployment} -> {target_deployment}"

    @beta_tool
    def check_internet_reachability(target_deployment: str) -> str:
        """Check whether external internet traffic can reach the given Deployment's pods, honoring NetworkPolicies.

        Args:
            target_deployment: Name of the target Deployment.
        """
        target = _find_deployment(target_deployment)
        if not target:
            return f"Error: deployment {target_deployment} not found"
        allowed = can_external_reach(target, policies)
        verdict = "ALLOWED" if allowed else "BLOCKED_BY_NETWORK_POLICY"
        return f"{verdict}: Internet -> {target_deployment}"

    return [
        list_services,
        list_deployments,
        list_network_policies,
        check_pod_reachability,
        check_internet_reachability,
    ]


def generate_llm_explanation(cluster_state, findings, verbose=True):
    import sys

    def _log(msg):
        if verbose:
            print(f"  [llm] {msg}", file=sys.stderr, flush=True)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None

    try:
        from anthropic import Anthropic
    except ImportError:
        return None

    tools = _build_tools(cluster_state)
    client = Anthropic()

    rule_findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['title']}: {f['details']}"
        + (" | Path: " + " -> ".join(f["path"]) if f.get("path") else "")
        for f in findings
    ) or "- (no rule-engine findings)"

    user_prompt = (
        "Rule-engine findings for the current cluster:\n"
        f"{rule_findings_text}\n\n"
        "Use your tools to verify which attack paths are real, then write the final "
        "security analysis."
    )

    _log("contacting claude-opus-4-7 with 5 tools and adaptive thinking...")

    try:
        runner = client.beta.messages.tool_runner(
            model="claude-opus-4-7",
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tools,
            messages=[{"role": "user", "content": user_prompt}],
        )
    except Exception as exc:
        _log(f"API request failed: {type(exc).__name__}: {exc}")
        return None

    final_text = ""
    tool_calls = 0
    turn = 0
    try:
        for message in runner:
            turn += 1
            for block in message.content:
                if block.type == "tool_use":
                    tool_calls += 1
                    _log(f"tool call #{tool_calls}: {block.name}({dict(block.input)})")
                elif block.type == "text" and block.text.strip():
                    final_text = block.text
            _log(f"turn {turn} complete (stop_reason={getattr(message, 'stop_reason', '?')})")
    except Exception as exc:
        _log(f"agent loop failed: {type(exc).__name__}: {exc}")
        return None

    if not final_text:
        _log("no final text produced")
        return None
    return f"{final_text}\n\n[LLM agent made {tool_calls} tool call(s) across {turn} turn(s).]"
