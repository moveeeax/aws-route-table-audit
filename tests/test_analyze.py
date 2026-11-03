"""Rule-by-rule tests against JSON fixtures: no AWS, no credentials, no moto."""

from __future__ import annotations

import pytest
from conftest import findings_for, payload, route, rules, subnet, table, table_in

from aws_route_table_audit.analyze import (
    PayloadError,
    analyze,
    exit_code,
    route_target,
    worst,
)


def test_clean_vpc_has_no_findings(clean):
    result = analyze(clean)
    assert result["summary"]["severity"] == "ok"
    assert result["summary"]["findings"] == 0
    assert [t["severity"] for t in result["tables"]] == ["ok", "ok"]


def test_blackholed_default_route_is_critical_and_names_the_dead_nat(broken):
    result = analyze(broken)
    blackholes = findings_for(result, "blackhole-route")
    assert len(blackholes) == 1
    finding = blackholes[0]
    assert finding["severity"] == "critical"
    assert finding["destination"] == "0.0.0.0/0"
    assert finding["target"] == "nat-0deadbeef"
    assert "nat-0deadbeef" in finding["message"]
    assert "nat gateway" in finding["message"]


def test_blackholed_route_does_not_also_report_a_missing_default(broken):
    # The route exists, it is just dead. Reporting both would double-count one problem.
    assert "no-default-route" not in rules(analyze(broken), "rtb-0bad-workers")


def test_implicit_main_table_subnet_is_warn():
    result = analyze(
        payload(
            [table(main=True, routes=[route("10.0.0.0/16", GatewayId="local")])],
            [subnet("subnet-orphan", "10.0.5.0/24")],
        )
    )
    findings = findings_for(result, "implicit-main-association")
    assert [f["severity"] for f in findings] == ["warn"]
    assert findings[0]["subnet_id"] == "subnet-orphan"
    assert "10.0.5.0/24" in findings[0]["message"]
    assert table_in(result, "rtb-1")["implicit_subnets"] == ["subnet-orphan"]


def test_implicit_main_table_becomes_critical_when_private_subnet_defaults_to_igw(broken):
    findings = {
        f["subnet_id"]: f
        for f in findings_for(analyze(broken), "implicit-main-association")
    }
    assert findings["subnet-0bad-orphan-private"]["severity"] == "critical"
    assert "igw-0bad" in findings["subnet-0bad-orphan-private"]["message"]
    # Auto-assign-public subnets on an igw table are just public subnets.
    assert findings["subnet-0bad-orphan-public"]["severity"] == "warn"


def test_explicitly_associated_private_subnet_on_an_igw_table_is_critical(broken):
    findings = findings_for(analyze(broken), "private-subnet-via-igw")
    assert [f["subnet_id"] for f in findings] == ["subnet-0bad-dupe-private"]
    assert findings[0]["severity"] == "critical"
    assert "igw-0bad" in findings[0]["message"]


def test_public_subnet_on_an_igw_table_is_not_reported(clean):
    assert findings_for(analyze(clean), "private-subnet-via-igw") == []


def test_table_without_a_default_route_is_warn(broken):
    result = analyze(broken)
    findings = findings_for(result, "no-default-route")
    assert len(findings) == 1
    assert findings[0]["severity"] == "warn"
    assert table_in(result, "rtb-0bad-isolated")["severity"] == "warn"


def test_two_default_routes_are_reported_once_with_both_targets(broken):
    findings = findings_for(analyze(broken), "duplicate-default-route")
    assert len(findings) == 1
    assert findings[0]["severity"] == "warn"
    assert "igw-0bad" in findings[0]["message"]
    assert "nat-0live" in findings[0]["message"]


def test_contained_cidrs_are_an_overlap_and_the_longer_prefix_wins():
    result = analyze(
        payload(
            [
                table(
                    routes=[
                        route("10.0.0.0/16", VpcPeeringConnectionId="pcx-1"),
                        route("10.0.1.0/24", TransitGatewayId="tgw-1"),
                    ]
                )
            ]
        )
    )
    findings = findings_for(result, "shadowed-overlap")
    assert len(findings) == 1
    assert findings[0]["destination"] == "10.0.0.0/16"
    assert findings[0]["shadowed_by"] == "10.0.1.0/24"
    assert "10.0.1.0/24 wins by longest-prefix match" in findings[0]["message"]


def test_disjoint_cidrs_are_not_an_overlap():
    result = analyze(
        payload(
            [
                table(
                    routes=[
                        route("10.0.1.0/24", TransitGatewayId="tgw-1"),
                        route("10.0.2.0/24", TransitGatewayId="tgw-2"),
                    ]
                )
            ]
        )
    )
    assert findings_for(result, "shadowed-overlap") == []


def test_a_default_route_does_not_shadow_specific_routes():
    result = analyze(
        payload(
            [
                table(
                    routes=[
                        route("0.0.0.0/0", NatGatewayId="nat-1"),
                        route("10.0.0.0/16", GatewayId="local"),
                        route("192.168.0.0/24", VpcPeeringConnectionId="pcx-1"),
                    ]
                )
            ]
        )
    )
    assert findings_for(result, "shadowed-overlap") == []


def test_overlap_ignores_prefix_lists_and_mixed_families():
    result = analyze(
        payload(
            [
                table(
                    routes=[
                        {
                            "DestinationPrefixListId": "pl-1",
                            "GatewayId": "vpce-1",
                            "State": "active",
                        },
                        route("10.0.0.0/16", GatewayId="local"),
                        {
                            "DestinationIpv6CidrBlock": "::/0",
                            "EgressOnlyInternetGatewayId": "eigw-1",
                            "State": "active",
                        },
                    ]
                )
            ]
        )
    )
    assert findings_for(result, "shadowed-overlap") == []


def test_tables_are_sorted_by_worst_finding(broken):
    severities = [t["severity"] for t in analyze(broken)["tables"]]
    assert severities == sorted(severities, key=lambda s: -["ok", "warn", "critical"].index(s))
    assert severities[0] == "critical"


def test_summary_counts_tables_and_findings(broken):
    summary = analyze(broken)["summary"]
    assert summary["tables"] == 4
    assert summary["severity"] == "critical"
    assert summary["tables_by_severity"]["critical"] == 3
    assert summary["tables_by_severity"]["warn"] == 1
    assert summary["findings"] == sum(summary["findings_by_severity"].values())


def test_implicit_subnets_are_scoped_to_their_own_vpc():
    result = analyze(
        payload(
            [
                table(
                    "rtb-a", "vpc-a", main=True, routes=[route("10.0.0.0/16", GatewayId="local")]
                ),
                table(
                    "rtb-b", "vpc-b", main=True, routes=[route("10.1.0.0/16", GatewayId="local")]
                ),
            ],
            [subnet("subnet-a", "10.0.1.0/24", vpc_id="vpc-a")],
        )
    )
    assert table_in(result, "rtb-a")["implicit_subnets"] == ["subnet-a"]
    assert table_in(result, "rtb-b")["implicit_subnets"] == []


def test_a_subnet_associated_elsewhere_is_not_implicit_on_the_main_table():
    result = analyze(
        payload(
            [
                table("rtb-main", main=True, routes=[route("0.0.0.0/0", GatewayId="igw-1")]),
                table(
                    "rtb-priv",
                    subnets=["subnet-priv"],
                    routes=[route("0.0.0.0/0", NatGatewayId="nat-1")],
                ),
            ],
            [subnet("subnet-priv", "10.0.1.0/24")],
        )
    )
    assert findings_for(result, "implicit-main-association") == []


@pytest.mark.parametrize(
    ("route_dict", "expected"),
    [
        ({"GatewayId": "local"}, ("local", "local")),
        ({"GatewayId": "igw-1"}, ("internet gateway", "igw-1")),
        ({"GatewayId": "vgw-1"}, ("virtual private gateway", "vgw-1")),
        ({"GatewayId": "vpce-1"}, ("vpc endpoint", "vpce-1")),
        ({"NatGatewayId": "nat-1"}, ("nat gateway", "nat-1")),
        ({"NetworkInterfaceId": "eni-1"}, ("network interface", "eni-1")),
        ({"TransitGatewayId": "tgw-1"}, ("transit gateway", "tgw-1")),
        ({}, ("unknown target", "")),
    ],
)
def test_route_target_naming(route_dict, expected):
    assert route_target(route_dict) == expected


@pytest.mark.parametrize(
    ("fail_on", "fixture", "expected"),
    [
        ("critical", "broken", 1),
        ("warn", "broken", 1),
        ("none", "broken", 0),
        ("critical", "clean", 0),
        ("warn", "clean", 0),
    ],
)
def test_exit_code_threshold(fail_on, fixture, expected, request):
    report = analyze(request.getfixturevalue(fixture))
    assert exit_code(report, fail_on) == expected


def test_warn_only_report_fails_on_warn_but_not_on_critical():
    report = analyze(
        payload([table(routes=[route("10.0.0.0/16", GatewayId="local")])])
    )
    assert report["summary"]["severity"] == "warn"
    assert exit_code(report, "warn") == 1
    assert exit_code(report, "critical") == 0


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"subnets": []},
        {"route_tables": {}},
        {"route_tables": [{"VpcId": "vpc-1"}]},
        {"route_tables": [{"RouteTableId": "rtb-1"}]},
        {"route_tables": [], "subnets": [{"CidrBlock": "10.0.0.0/24"}]},
    ],
)
def test_malformed_payloads_raise_payload_error(bad):
    with pytest.raises(PayloadError):
        analyze(bad)


def test_raw_describe_shapes_are_accepted():
    result = analyze(
        {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-1",
                    "VpcId": "vpc-1",
                    "Routes": [route("0.0.0.0/0", NatGatewayId="nat-1")],
                }
            ],
            "Subnets": [],
        }
    )
    assert result["summary"]["severity"] == "ok"
    assert result["region"] is None


def test_worst_severity():
    assert worst([]) == "ok"
    assert worst(["ok", "warn"]) == "warn"
    assert worst(["warn", "critical", "ok"]) == "critical"
