import ipaddress

def parse_allowlist(cidrs: list[str]):
    if not cidrs:
        raise ValueError("At least one approved CIDR is required.")
    networks = []
    for raw in cidrs:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {raw}") from exc
        if not (net.is_private or net.is_loopback or net.is_link_local):
            raise ValueError(f"Public CIDR is blocked by this MVP: {raw}")
        networks.append(net)
    return networks

def validate_target(target_text: str, networks):
    try:
        target = ipaddress.ip_address(target_text)
    except ValueError as exc:
        raise ValueError("Use a literal IP address; hostnames are not accepted.") from exc
    if not (target.is_private or target.is_loopback or target.is_link_local):
        raise ValueError("Public targets are blocked. Use an authorized private lab target.")
    if not any(target.version == n.version and target in n for n in networks):
        raise ValueError("Target is outside the approved CIDR allowlist.")
    return target
