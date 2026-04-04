"""Raw firewall rule management for inter-tunnel routing."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from .models import IPSecTunnel, RouteRule, WireGuardTunnel
from .utils import console, run

SYSCTL_CONF = Path("/etc/sysctl.d/99-vpnplane.conf")

FORWARD_CHAIN = "VPNPLANE_FORWARD"
INPUT_CHAIN = "VPNPLANE_INPUT"
NAT_CHAIN = "VPNPLANE_NAT"
COMMENT_PREFIX = "wg-route:"

SYSCTL_SETTINGS = {
    "net.ipv4.ip_forward": "1",
    "net.ipv6.conf.all.forwarding": "1",
    # Loose mode keeps anti-spoofing while still allowing asymmetric routed VPN paths.
    "net.ipv4.conf.all.rp_filter": "2",
    "net.ipv4.conf.default.rp_filter": "2",
}


# ---------------------------------------------------------------------------
# Top-level apply / cleanup
# ---------------------------------------------------------------------------


def apply_firewall(
    routes: list[RouteRule],
    wg_tunnels: list[WireGuardTunnel],
    ipsec_tunnels: list[IPSecTunnel],
    dry_run: bool = False,
) -> None:
    """Apply all managed firewall state: sysctl and forwarding/input rules."""
    managed_ifaces = {t.name for t in wg_tunnels} | {t.name for t in ipsec_tunnels}
    managed_subnets = _collect_managed_subnets(wg_tunnels, ipsec_tunnels)
    _apply_sysctl(dry_run)
    _apply_input_rules(wg_tunnels, dry_run)
    _apply_filter_rules(routes, managed_ifaces, managed_subnets, dry_run)
    _apply_nat_rules(routes, managed_ifaces, dry_run)


def reset_firewall_managed_state(dry_run: bool = False) -> None:
    """Delete managed firewall chains/jumps so apply can render a clean state."""
    # Remove managed jumps first so chains can be deleted cleanly.
    _remove_jump("filter", "INPUT", INPUT_CHAIN, dry_run)
    _remove_jump("filter", "FORWARD", FORWARD_CHAIN, dry_run)
    _remove_jump("nat", "POSTROUTING", NAT_CHAIN, dry_run)

    _delete_chain("filter", INPUT_CHAIN, dry_run)
    _delete_chain("filter", FORWARD_CHAIN, dry_run)
    _delete_chain("nat", NAT_CHAIN, dry_run)

    _remove_jump("filter", "INPUT", INPUT_CHAIN, dry_run, binary="ip6tables")
    _remove_jump("filter", "FORWARD", FORWARD_CHAIN, dry_run, binary="ip6tables")
    _remove_jump("nat", "POSTROUTING", NAT_CHAIN, dry_run, binary="ip6tables")
    _delete_chain("filter", INPUT_CHAIN, dry_run, binary="ip6tables")
    _delete_chain("filter", FORWARD_CHAIN, dry_run, binary="ip6tables")
    _delete_chain("nat", NAT_CHAIN, dry_run, binary="ip6tables")


def cleanup_firewall_managed_state(dry_run: bool = False) -> None:
    """Disable all connector-managed firewall state including sysctl file."""
    reset_firewall_managed_state(dry_run=dry_run)

    if SYSCTL_CONF.exists():
        if dry_run:
            console.print(f"[dim]DRY-RUN:[/dim] would delete {SYSCTL_CONF}")
        else:
            SYSCTL_CONF.unlink()

    # Apply neutral runtime values immediately during disable.
    run(["sysctl", "-w", "net.ipv4.ip_forward=0"], dry_run=dry_run)
    run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"], dry_run=dry_run)


# ---------------------------------------------------------------------------
# sysctl
# ---------------------------------------------------------------------------


def _apply_sysctl(dry_run: bool) -> None:
    content = "# managed-by: vpnplane\n"
    content += "\n".join(f"{k} = {v}" for k, v in SYSCTL_SETTINGS.items()) + "\n"

    existing = SYSCTL_CONF.read_text() if SYSCTL_CONF.exists() else None
    if content != existing:
        if dry_run:
            console.print(f"[dim]DRY-RUN:[/dim] would write {SYSCTL_CONF}")
        else:
            SYSCTL_CONF.parent.mkdir(parents=True, exist_ok=True)
            SYSCTL_CONF.write_text(content)

    for key, value in SYSCTL_SETTINGS.items():
        run(["sysctl", "-w", f"{key}={value}"], dry_run=dry_run)

    console.print("[green]  sysctl: forwarding configured[/green]")


# ---------------------------------------------------------------------------
# iptables helpers
# ---------------------------------------------------------------------------


def _ensure_chain(table: str, chain: str, dry_run: bool, binary: str = "iptables") -> None:
    """Create a chain if missing."""
    created = run(
        [binary, "-t", table, "-N", chain],
        check=False,
        dry_run=dry_run,
        capture=True,
    )
    if not dry_run and created.returncode == 0:
        console.print(f"[green]  {binary}: created chain {chain} ({table})[/green]")


def _ensure_jump(
    table: str,
    parent_chain: str,
    target_chain: str,
    dry_run: bool,
    binary: str = "iptables",
) -> None:
    """Ensure parent chain jumps to target chain exactly once."""
    exists = run(
        [binary, "-t", table, "-C", parent_chain, "-j", target_chain],
        check=False,
        dry_run=dry_run,
        capture=True,
    )
    if dry_run or exists.returncode == 0:
        return
    run([binary, "-t", table, "-I", parent_chain, "1", "-j", target_chain], dry_run=False)


def _remove_jump(
    table: str,
    parent_chain: str,
    target_chain: str,
    dry_run: bool,
    binary: str = "iptables",
) -> None:
    """Remove all jumps from parent_chain to target_chain."""
    while True:
        result = run(
            [binary, "-t", table, "-D", parent_chain, "-j", target_chain],
            check=False,
            capture=True,
            dry_run=dry_run,
        )
        if dry_run or result.returncode != 0:
            break


def _delete_chain(table: str, chain: str, dry_run: bool, binary: str = "iptables") -> None:
    """Flush and delete a chain if it exists."""
    run([binary, "-t", table, "-F", chain], check=False, capture=True, dry_run=dry_run)
    run([binary, "-t", table, "-X", chain], check=False, capture=True, dry_run=dry_run)


# ---------------------------------------------------------------------------
# Filter chains (forwarding/input)
# ---------------------------------------------------------------------------


def _apply_input_rules(tunnels: list[WireGuardTunnel], dry_run: bool) -> None:
    """Allow configured WireGuard UDP listen ports via a managed INPUT chain."""
    for binary in ("iptables", "ip6tables"):
        _ensure_chain("filter", INPUT_CHAIN, dry_run, binary=binary)
        _ensure_jump("filter", "INPUT", INPUT_CHAIN, dry_run, binary=binary)
        run([binary, "-t", "filter", "-F", INPUT_CHAIN], dry_run=dry_run)

        opened = 0
        for tunnel in tunnels:
            if tunnel.listen_port is None:
                continue
            run(
                [
                    binary,
                    "-t",
                    "filter",
                    "-A",
                    INPUT_CHAIN,
                    "-p",
                    "udp",
                    "--dport",
                    str(tunnel.listen_port),
                    "-m",
                    "comment",
                    "--comment",
                    f"wg-input:{tunnel.name}",
                    "-j",
                    "ACCEPT",
                ],
                dry_run=dry_run,
            )
            opened += 1

        run(
            [
                binary,
                "-t",
                "filter",
                "-A",
                INPUT_CHAIN,
                "-m",
                "comment",
                "--comment",
                "wg-input:return",
                "-j",
                "RETURN",
            ],
            dry_run=dry_run,
        )

        if opened:
            console.print(
                f"[green]  {binary} input: {opened} WireGuard listen port rule(s) applied[/green]"
            )
        else:
            console.print(f"[dim]  {binary} input: no WireGuard listen ports configured[/dim]")


def _is_default_ipv4_subnet(subnet: str | None) -> bool:
    return subnet == "0.0.0.0/0"


def _is_default_ipv6_subnet(subnet: str | None) -> bool:
    return subnet == "::/0"


def _is_default_subnet(subnet: str | None) -> bool:
    return _is_default_ipv4_subnet(subnet) or _is_default_ipv6_subnet(subnet)


def _subnet_ip_version(subnet: str | None) -> int | None:
    if subnet is None:
        return None
    return ipaddress.ip_network(subnet, strict=False).version


def _is_internet_egress_route(route: RouteRule, managed_ifaces: set[str]) -> bool:
    """Detect routes that should NAT roadwarrior traffic out of the host."""
    if route.action != "allow":
        return False

    # Internet egress is only meaningful when destination exits via a non-managed interface.
    if route.to.interface in managed_ifaces:
        return False

    # Explicit default route, e.g. 0.0.0.0/0 or ::/0.
    if any(
        _is_default_ipv4_subnet(subnet) or _is_default_ipv6_subnet(subnet)
        for subnet in route.to.subnets
    ):
        return True

    return False


def _order_routes(routes: list[RouteRule], managed_ifaces: set[str]) -> list[RouteRule]:
    """Ensure broad internet egress routes are rendered after specific routes."""
    regular = [r for r in routes if not _is_internet_egress_route(r, managed_ifaces)]
    internet = [r for r in routes if _is_internet_egress_route(r, managed_ifaces)]
    return regular + internet


def _collect_managed_subnets(
    wg_tunnels: list[WireGuardTunnel], ipsec_tunnels: list[IPSecTunnel]
) -> set[str]:
    """Collect tunnel networks that represent managed VPN domains."""
    subnets: set[str] = set()

    for tunnel in wg_tunnels:
        iface_subnet = str(ipaddress.ip_interface(tunnel.interface_address()).network)
        if not _is_default_subnet(iface_subnet):
            subnets.add(iface_subnet)

        # Treat peer AllowedIPs as managed tunnel destinations for default deny.
        if tunnel.peer:
            for peer_subnet in tunnel.peer.allowed_ips:
                canonical = str(ipaddress.ip_network(peer_subnet, strict=False))
                if _is_default_subnet(canonical):
                    continue
                subnets.add(canonical)

    for tunnel in ipsec_tunnels:
        for subnet in tunnel.local.subnets + tunnel.remote.subnets:
            canonical = str(ipaddress.ip_network(subnet, strict=False))
            if _is_default_subnet(canonical):
                continue
            subnets.add(canonical)

    return subnets


def _apply_filter_rules(
    routes: list[RouteRule],
    managed_ifaces: set[str],
    managed_subnets: set[str],
    dry_run: bool,
) -> None:
    ordered_routes = _order_routes(routes, managed_ifaces)

    for binary, family in (("iptables", 4), ("ip6tables", 6)):
        _ensure_chain("filter", FORWARD_CHAIN, dry_run, binary=binary)
        _ensure_jump("filter", "FORWARD", FORWARD_CHAIN, dry_run, binary=binary)
        run([binary, "-t", "filter", "-F", FORWARD_CHAIN], dry_run=dry_run)

        run(
            [
                binary,
                "-t",
                "filter",
                "-A",
                FORWARD_CHAIN,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-m",
                "comment",
                "--comment",
                "wg-forward:stateful",
                "-j",
                "ACCEPT",
            ],
            dry_run=dry_run,
        )

        rendered = 0
        for route in ordered_routes:
            for cmd in _build_filter_rule_commands(route, binary=binary, family=family):
                run(cmd, dry_run=dry_run)
                rendered += 1

        # Default deny: managed tunnel subnets cannot forward anywhere unless
        # explicitly allowed by route rules rendered above.
        default_drops = _build_default_managed_subnet_egress_drop_commands(
            managed_subnets,
            binary=binary,
            family=family,
        )
        for cmd in default_drops:
            run(cmd, dry_run=dry_run)
            rendered += 1

        # Do not force a global drop here; return to parent policy for non-managed traffic.
        run(
            [
                binary,
                "-t",
                "filter",
                "-A",
                FORWARD_CHAIN,
                "-m",
                "comment",
                "--comment",
                "wg-forward:return",
                "-j",
                "RETURN",
            ],
            dry_run=dry_run,
        )

        if routes:
            console.print(
                f"[green]  {binary} filter: {rendered} managed forwarding rule(s) applied[/green]"
            )
        else:
            console.print(
                f"[dim]  {binary} filter: no route rules configured"
                f" ({len(default_drops)} default managed-subnet drop rule(s) applied)[/dim]"
            )


def _build_default_managed_subnet_egress_drop_commands(
    managed_subnets: set[str], *, binary: str, family: int
) -> list[list[str]]:
    """Build DROP rules for forwarding sourced from managed tunnel subnets."""
    commands: list[list[str]] = []
    subnets = sorted(s for s in managed_subnets if _subnet_applies_to_family(s, family))
    for src_subnet in subnets:
        commands.append(
            [
                binary,
                "-t",
                "filter",
                "-A",
                FORWARD_CHAIN,
                "-s",
                src_subnet,
                "-m",
                "comment",
                "--comment",
                "wg-forward:default-managed-subnet-egress-drop",
                "-j",
                "DROP",
            ]
        )
    return commands


def _apply_nat_rules(routes: list[RouteRule], managed_ifaces: set[str], dry_run: bool) -> None:
    """Apply NAT MASQUERADE rules for internet egress routes."""
    for binary, family in (("iptables", 4), ("ip6tables", 6)):
        _ensure_chain("nat", NAT_CHAIN, dry_run, binary=binary)
        _ensure_jump("nat", "POSTROUTING", NAT_CHAIN, dry_run, binary=binary)
        run([binary, "-t", "nat", "-F", NAT_CHAIN], dry_run=dry_run)

        rendered = 0
        for route in _order_routes(routes, managed_ifaces):
            if not _is_internet_egress_route(route, managed_ifaces):
                continue

            src_subnets = route.from_.subnets or [None]
            dst_subnets = route.to.subnets or [None]
            if not any(_subnet_applies_to_family(dst_subnet, family) for dst_subnet in dst_subnets):
                continue

            for src_subnet in src_subnets:
                if not _subnet_applies_to_family(src_subnet, family):
                    continue

                cmd = [
                    binary,
                    "-t",
                    "nat",
                    "-A",
                    NAT_CHAIN,
                    "-o",
                    route.to.interface,
                ]
                if src_subnet:
                    cmd += ["-s", src_subnet]
                cmd += [
                    "-m",
                    "comment",
                    "--comment",
                    f"{COMMENT_PREFIX}{route.name}:nat",
                    "-j",
                    "MASQUERADE",
                ]
                run(cmd, dry_run=dry_run)
                rendered += 1

        run(
            [
                binary,
                "-t",
                "nat",
                "-A",
                NAT_CHAIN,
                "-m",
                "comment",
                "--comment",
                "wg-nat:return",
                "-j",
                "RETURN",
            ],
            dry_run=dry_run,
        )

        if rendered:
            console.print(f"[green]  {binary} nat: {rendered} MASQUERADE rule(s) applied[/green]")
        else:
            console.print(f"[dim]  {binary} nat: no internet egress rules configured[/dim]")


def _subnet_applies_to_family(subnet: str | None, family: int) -> bool:
    version = _subnet_ip_version(subnet)
    return version is None or version == family


def _family_protocol(protocol: str, family: int) -> str:
    if protocol == "icmp" and family == 6:
        return "icmpv6"
    return protocol


def _build_filter_rule_commands(route: RouteRule, *, binary: str, family: int) -> list[list[str]]:
    action = "ACCEPT" if route.action == "allow" else "DROP"
    commands: list[list[str]] = []

    src_subnets = route.from_.subnets or [None]
    dst_subnets = route.to.subnets or [None]

    for src_subnet in src_subnets:
        if not _subnet_applies_to_family(src_subnet, family):
            continue
        for dst_subnet in dst_subnets:
            if not _subnet_applies_to_family(dst_subnet, family):
                continue
            commands.append(
                _build_single_filter_rule(
                    binary=binary,
                    in_iface=route.from_.interface,
                    out_iface=route.to.interface,
                    src_subnet=src_subnet,
                    dst_subnet=dst_subnet,
                    protocol=_family_protocol(route.protocol, family),
                    ports=route.ports,
                    target=action,
                    comment=f"{COMMENT_PREFIX}{route.name}:fwd",
                )
            )

            if route.bidirectional and route.action == "allow":
                commands.append(
                    _build_single_filter_rule(
                        binary=binary,
                        in_iface=route.to.interface,
                        out_iface=route.from_.interface,
                        src_subnet=dst_subnet,
                        dst_subnet=src_subnet,
                        protocol=_family_protocol(route.protocol, family),
                        ports=route.ports,
                        target=action,
                        comment=f"{COMMENT_PREFIX}{route.name}:rev",
                    )
                )

    return commands


def _build_single_filter_rule(
    *,
    binary: str,
    in_iface: str,
    out_iface: str,
    src_subnet: str | None,
    dst_subnet: str | None,
    protocol: str,
    ports: list[int],
    target: str,
    comment: str,
) -> list[str]:
    cmd = [binary, "-t", "filter", "-A", FORWARD_CHAIN, "-i", in_iface, "-o", out_iface]

    if src_subnet:
        cmd += ["-s", src_subnet]
    if dst_subnet:
        cmd += ["-d", dst_subnet]

    if protocol != "any":
        cmd += ["-p", protocol]

    if ports:
        cmd += ["-m", "multiport", "--dports", ",".join(str(p) for p in ports)]

    cmd += ["-m", "comment", "--comment", comment, "-j", target]
    return cmd


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def get_firewall_status() -> list[dict]:
    """Return active managed forwarding rules from IPv4 and IPv6 managed chains."""
    grouped: dict[str, list[str]] = {}
    for binary in ("iptables", "ip6tables"):
        listing = run(
            [binary, "-t", "filter", "-S", FORWARD_CHAIN],
            check=False,
            capture=True,
        )
        if listing.returncode != 0:
            continue

        for line in listing.stdout.splitlines():
            marker = f'--comment "{COMMENT_PREFIX}'
            if marker not in line:
                continue

            comment_start = line.find(marker)
            comment_end = line.find('"', comment_start + len(marker))
            if comment_end == -1:
                continue

            raw_name = line[comment_start + len(marker):comment_end]
            rule_name = raw_name.split(":", 1)[0]
            grouped.setdefault(rule_name, []).append(f"[{binary}] {line}")

    return [{"name": name, "rules": rules} for name, rules in grouped.items()]


def get_system_status() -> dict:
    """Return forwarding and managed chain health for status output."""
    ipv4_forward = _read_sysctl_bool("net.ipv4.ip_forward")
    ipv6_forward = _read_sysctl_bool("net.ipv6.conf.all.forwarding")

    chain_checks: dict[str, bool] = {}
    rule_count = 0
    for binary in ("iptables", "ip6tables"):
        listing = run(
            [binary, "-t", "filter", "-S", FORWARD_CHAIN],
            check=False,
            capture=True,
        )
        present = listing.returncode == 0
        chain_checks[binary] = present
        if present:
            # Exclude chain policy line itself, count actual rules.
            rule_count += len([line for line in listing.stdout.splitlines() if line.startswith("-A")])

    return {
        "ipv4_forward": ipv4_forward,
        "ipv6_forward": ipv6_forward,
        "chains_present": all(chain_checks.values()),
        "rule_count": rule_count,
    }


def _read_sysctl_bool(key: str) -> bool | None:
    result = run(["sysctl", "-n", key], check=False, capture=True)
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if value in {"1", "on", "true"}:
        return True
    if value in {"0", "off", "false"}:
        return False
    return None
