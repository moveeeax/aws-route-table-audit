"""The rule engine.

Input is a payload of plain dicts straight out of ``describe_route_tables``,
``describe_subnets`` and ``describe_prefix_lists`` (see
:mod:`aws_route_table_audit.collect`). Output is a report of findings per route table.
Nothing in here talks to AWS, which is why every rule can be tested against a JSON
fixture.
"""

from __future__ import annotations

import ipaddress
import re
from itertools import combinations

SEVERITIES = ("ok", "warn", "critical")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}

DEFAULT_ROUTE = "0.0.0.0/0"
DEFAULT_ROUTE_V6 = "::/0"

#: Route target attributes, most specific first. ``GatewayId`` is last because it is
#: the catch-all that carries igw-, vgw-, vpce- and the literal ``local``.
_TARGET_KEYS = (
    ("NatGatewayId", "nat gateway"),
    ("TransitGatewayId", "transit gateway"),
    ("VpcPeeringConnectionId", "peering connection"),
    ("NetworkInterfaceId", "network interface"),
    ("InstanceId", "instance"),
    ("EgressOnlyInternetGatewayId", "egress-only internet gateway"),
    ("CarrierGatewayId", "carrier gateway"),
    ("LocalGatewayId", "local gateway"),
    ("CoreNetworkArn", "core network"),
    ("GatewayId", "gateway"),
)

_GATEWAY_PREFIXES = (
    ("igw-", "internet gateway"),
    ("vgw-", "virtual private gateway"),
    ("vpce-", "vpc endpoint"),
    ("eigw-", "egress-only internet gateway"),
)


#: AWS-managed prefix lists of the two services that have free gateway endpoints:
#: ``com.amazonaws.<region>.s3`` and ``.dynamodb``, with a ``cn.`` prefix in China regions.
#: Anchored, so ``s3express`` and other service prefix lists do not match.
_GATEWAY_SERVICE_RE = re.compile(r"^(?:cn\.)?com\.amazonaws\.[a-z0-9-]+\.(s3|dynamodb)$")
_GATEWAY_SERVICE_LABELS = {"s3": "S3", "dynamodb": "DynamoDB"}

#: The one rule that needs ``prefix_lists`` in the payload. Without them it is skipped,
#: and the report says so under ``skipped_rules``.
GATEWAY_ENDPOINT_RULE = "missing-gateway-endpoint"


class PayloadError(ValueError):
    """The payload is not a shape this tool understands."""


def worst(severities) -> str:
    """Return the highest severity in *severities*, ``ok`` when empty."""
    return max(severities, key=lambda s: _RANK.get(s, 0), default="ok")


def rank(severity: str) -> int:
    """Sort key for a severity name."""
    return _RANK.get(severity, 0)


def route_target(route: dict) -> tuple[str, str]:
    """Return ``(kind, id)`` for a route's target, e.g. ``("nat gateway", "nat-0a1")``."""
    for key, kind in _TARGET_KEYS:
        value = route.get(key)
        if not value:
            continue
        if key == "GatewayId":
            if value == "local":
                return "local", value
            for prefix, named in _GATEWAY_PREFIXES:
                if value.startswith(prefix):
                    return named, value
        return kind, value
    return "unknown target", ""


def route_destination(route: dict) -> str:
    """Return a route's destination: a CIDR, an IPv6 CIDR or a prefix list id."""
    for key in ("DestinationCidrBlock", "DestinationIpv6CidrBlock", "DestinationPrefixListId"):
        value = route.get(key)
        if value:
            return value
    return "?"


def table_name(table: dict) -> str:
    """The route table's ``Name`` tag, or an empty string."""
    for tag in table.get("Tags") or []:
        if tag.get("Key") == "Name":
            return tag.get("Value") or ""
    return ""


def _finding(rule: str, severity: str, message: str, **extra) -> dict:
    finding = {"rule": rule, "severity": severity, "message": message}
    finding.update({key: value for key, value in extra.items() if value not in (None, "")})
    return finding


def _validate(payload) -> tuple[list[dict], list[dict], list[dict] | None, str | None]:
    if not isinstance(payload, dict):
        raise PayloadError("payload must be a JSON object")
    tables = payload.get("route_tables", payload.get("RouteTables"))
    subnets = payload.get("subnets", payload.get("Subnets")) or []
    if not isinstance(tables, list):
        raise PayloadError("payload is missing a 'route_tables' list")
    if not isinstance(subnets, list):
        raise PayloadError("'subnets' must be a list")
    prefix_lists = payload.get("prefix_lists", payload.get("PrefixLists"))
    if prefix_lists is not None and not isinstance(prefix_lists, list):
        raise PayloadError("'prefix_lists' must be a list")
    for table in tables:
        if not isinstance(table, dict) or not table.get("RouteTableId"):
            raise PayloadError("every route table needs a 'RouteTableId'")
        if not table.get("VpcId"):
            raise PayloadError(f"route table {table['RouteTableId']} has no 'VpcId'")
    for subnet in subnets:
        if not isinstance(subnet, dict) or not subnet.get("SubnetId"):
            raise PayloadError("every subnet needs a 'SubnetId'")
    for prefix_list in prefix_lists or []:
        if not isinstance(prefix_list, dict) or not prefix_list.get("PrefixListId"):
            raise PayloadError("every prefix list needs a 'PrefixListId'")
    region = payload.get("region")
    return tables, subnets, prefix_lists, region if isinstance(region, str) else None


def _subnet_label(subnet_id: str, subnets_by_id: dict) -> str:
    subnet = subnets_by_id.get(subnet_id) or {}
    cidr = subnet.get("CidrBlock")
    return f"{subnet_id} ({cidr})" if cidr else subnet_id


def _is_private_subnet(subnet_id: str, subnets_by_id: dict) -> bool:
    """A subnet that does not auto-assign public IPs was meant to be private."""
    subnet = subnets_by_id.get(subnet_id)
    if subnet is None:
        return False
    return subnet.get("MapPublicIpOnLaunch") is False


def _live_defaults(routes: list[dict]) -> list[dict]:
    return [
        route
        for route in routes
        if route_destination(route) == DEFAULT_ROUTE and route.get("State") != "blackhole"
    ]


def _igw_default(routes: list[dict]) -> dict | None:
    for route in _live_defaults(routes):
        if route_target(route)[0] == "internet gateway":
            return route
    return None


def gateway_endpoint_lists(prefix_lists: list[dict]) -> dict[str, tuple[str, str]]:
    """Map S3/DynamoDB prefix list ids to ``(service, prefix list name)``."""
    found = {}
    for prefix_list in prefix_lists:
        name = prefix_list.get("PrefixListName") or ""
        match = _GATEWAY_SERVICE_RE.match(name)
        if match:
            found[prefix_list["PrefixListId"]] = (match.group(1), name)
    return found


def _blackhole_findings(routes: list[dict]) -> list[dict]:
    findings = []
    for route in routes:
        if route.get("State") != "blackhole":
            continue
        destination = route_destination(route)
        kind, target = route_target(route)
        target_text = f"{kind} {target}".strip()
        findings.append(
            _finding(
                "blackhole-route",
                "critical",
                f"route to {destination} is blackholed: {target_text} no longer exists",
                destination=destination,
                target=target,
                target_kind=kind,
            )
        )
    return findings


def _default_route_findings(routes: list[dict]) -> list[dict]:
    findings = []
    defaults = [route for route in routes if route_destination(route) == DEFAULT_ROUTE]
    if not defaults:
        findings.append(
            _finding(
                "no-default-route",
                "warn",
                f"no {DEFAULT_ROUTE} route: anything not matching a local route is dropped",
                destination=DEFAULT_ROUTE,
            )
        )
        return findings
    live = _live_defaults(routes)
    if len(live) > 1:
        targets = sorted(f"{kind} {ident}".strip() for kind, ident in map(route_target, live))
        findings.append(
            _finding(
                "duplicate-default-route",
                "warn",
                f"{len(live)} default routes compete for {DEFAULT_ROUTE}: {', '.join(targets)}",
                destination=DEFAULT_ROUTE,
            )
        )
    return findings


def _private_via_igw_findings(routes, subnet_ids, subnets_by_id) -> list[dict]:
    igw = _igw_default(routes)
    if igw is None:
        return []
    gateway = route_target(igw)[1]
    findings = []
    for subnet_id in subnet_ids:
        if not _is_private_subnet(subnet_id, subnets_by_id):
            continue
        findings.append(
            _finding(
                "private-subnet-via-igw",
                "critical",
                f"subnet {_subnet_label(subnet_id, subnets_by_id)} does not auto-assign public "
                f"IPs but its default route points at internet gateway {gateway}",
                subnet_id=subnet_id,
                destination=DEFAULT_ROUTE,
                target=gateway,
            )
        )
    return findings


def _implicit_association_findings(table, routes, implicit_subnets, subnets_by_id) -> list[dict]:
    igw = _igw_default(routes)
    gateway = route_target(igw)[1] if igw else ""
    table_id = table["RouteTableId"]
    findings = []
    for subnet_id in implicit_subnets:
        label = _subnet_label(subnet_id, subnets_by_id)
        private = _is_private_subnet(subnet_id, subnets_by_id)
        if igw and private:
            message = (
                f"subnet {label} has no route table association, so it inherits main table "
                f"{table_id}, which defaults to internet gateway {gateway}; the subnet does "
                f"not auto-assign public IPs and was meant to be private"
            )
            severity = "critical"
        else:
            message = (
                f"subnet {label} has no route table association and silently inherits main "
                f"table {table_id}"
            )
            severity = "warn"
        findings.append(
            _finding(
                "implicit-main-association",
                severity,
                message,
                subnet_id=subnet_id,
                target=gateway if igw and private else None,
            )
        )
    return findings


def _gateway_endpoint_findings(routes: list[dict], endpoint_lists: dict) -> list[dict]:
    """A NAT-routed table without a route to the S3 or DynamoDB gateway endpoint.

    Such traffic still works, it just goes through the NAT gateway and pays per-GB
    processing that a gateway endpoint would not charge. A blackholed prefix list route
    does not count as coverage: the endpoint behind it is gone.
    """
    nat = next(
        (route for route in _live_defaults(routes) if route_target(route)[0] == "nat gateway"),
        None,
    )
    if nat is None or not endpoint_lists:
        return []
    gateway = route_target(nat)[1]
    covered = {
        route["DestinationPrefixListId"]
        for route in routes
        if route.get("DestinationPrefixListId") and route.get("State") != "blackhole"
    }
    findings = []
    for prefix_list_id, (service, name) in sorted(endpoint_lists.items(), key=lambda i: i[1]):
        if prefix_list_id in covered:
            continue
        label = _GATEWAY_SERVICE_LABELS[service]
        findings.append(
            _finding(
                GATEWAY_ENDPOINT_RULE,
                "warn",
                f"no gateway endpoint route for {label} ({prefix_list_id}, {name}): its "
                f"traffic goes through nat gateway {gateway} and pays NAT data processing",
                destination=prefix_list_id,
                target=gateway,
                service=service,
            )
        )
    return findings


def _networks(routes: list[dict]):
    """Yield ``(network, route)`` for routes with a parseable IPv4/IPv6 destination."""
    for route in routes:
        destination = route_destination(route)
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        yield network, route


def _overlap_findings(routes: list[dict]) -> list[dict]:
    """Report routes shadowed by longest-prefix match.

    A default route next to specific routes is how routing is supposed to work, so
    ``0.0.0.0/0`` and ``::/0`` are never treated as the shadowing supernet.
    """
    findings = []
    pairs = list(_networks(routes))
    for (net_a, route_a), (net_b, route_b) in combinations(pairs, 2):
        if net_a.version != net_b.version or net_a == net_b:
            continue
        if net_a.prefixlen < net_b.prefixlen:
            supernet, sub, super_route, sub_route = net_a, net_b, route_a, route_b
        else:
            supernet, sub, super_route, sub_route = net_b, net_a, route_b, route_a
        if supernet.prefixlen == 0 or not sub.subnet_of(supernet):
            continue
        super_target = " ".join(route_target(super_route)).strip()
        sub_target = " ".join(route_target(sub_route)).strip()
        findings.append(
            _finding(
                "shadowed-overlap",
                "warn",
                f"{supernet} (via {super_target}) overlaps {sub} (via {sub_target}); "
                f"{sub} wins by longest-prefix match for addresses inside it",
                destination=str(supernet),
                shadowed_by=str(sub),
            )
        )
    return findings


def _analyze_table(table, implicit_subnets, subnets_by_id, endpoint_lists) -> dict:
    routes = table.get("Routes") or []
    associations = table.get("Associations") or []
    is_main = any(association.get("Main") for association in associations)
    associated = [a["SubnetId"] for a in associations if a.get("SubnetId")]

    findings = _blackhole_findings(routes)
    findings += _default_route_findings(routes)
    findings += _private_via_igw_findings(routes, associated, subnets_by_id)
    if is_main:
        findings += _implicit_association_findings(
            table, routes, implicit_subnets, subnets_by_id
        )
    findings += _overlap_findings(routes)
    findings += _gateway_endpoint_findings(routes, endpoint_lists)
    findings.sort(key=lambda f: (-rank(f["severity"]), f["rule"], f["message"]))

    return {
        "route_table_id": table["RouteTableId"],
        "vpc_id": table["VpcId"],
        "name": table_name(table),
        "main": is_main,
        "route_count": len(routes),
        "associated_subnets": sorted(associated),
        "implicit_subnets": sorted(implicit_subnets) if is_main else [],
        "severity": worst(f["severity"] for f in findings),
        "findings": findings,
    }


def analyze(payload) -> dict:
    """Turn a collected payload into a report.

    Raises :class:`PayloadError` when the payload is not describe-route-tables shaped.
    """
    tables, subnets, prefix_lists, region = _validate(payload)
    endpoint_lists = gateway_endpoint_lists(prefix_lists or [])
    skipped = {}
    if prefix_lists is None:
        skipped[GATEWAY_ENDPOINT_RULE] = (
            "payload has no prefix_lists (saved by an older version, or "
            "ec2:DescribePrefixLists was denied)"
        )
    subnets_by_id = {subnet["SubnetId"]: subnet for subnet in subnets}

    explicit: dict[str, set[str]] = {}
    for table in tables:
        for association in table.get("Associations") or []:
            subnet_id = association.get("SubnetId")
            if subnet_id:
                explicit.setdefault(table["VpcId"], set()).add(subnet_id)

    implicit_by_vpc: dict[str, list[str]] = {}
    for subnet in subnets:
        vpc_id = subnet.get("VpcId")
        if vpc_id and subnet["SubnetId"] not in explicit.get(vpc_id, set()):
            implicit_by_vpc.setdefault(vpc_id, []).append(subnet["SubnetId"])

    analyzed = [
        _analyze_table(
            table, implicit_by_vpc.get(table["VpcId"], []), subnets_by_id, endpoint_lists
        )
        for table in tables
    ]
    analyzed.sort(key=lambda t: (-rank(t["severity"]), t["route_table_id"]))

    findings = [f for t in analyzed for f in t["findings"]]
    return {
        "region": region,
        "tables": analyzed,
        "skipped_rules": skipped,
        "summary": {
            "tables": len(analyzed),
            "findings": len(findings),
            "severity": worst(t["severity"] for t in analyzed),
            "tables_by_severity": {
                name: sum(1 for t in analyzed if t["severity"] == name) for name in SEVERITIES
            },
            "findings_by_severity": {
                name: sum(1 for f in findings if f["severity"] == name) for name in SEVERITIES
            },
        },
    }


def exit_code(report: dict, fail_on: str) -> int:
    """``1`` when the report reaches the *fail_on* threshold, else ``0``."""
    if fail_on == "none":
        return 0
    return 1 if rank(report["summary"]["severity"]) >= rank(fail_on) else 0
