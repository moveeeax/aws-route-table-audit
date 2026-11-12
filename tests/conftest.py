"""Fixture loading plus small builders so each rule test shows only what it tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    with open(FIXTURES / name, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def clean() -> dict:
    return load("clean.json")


@pytest.fixture
def broken() -> dict:
    return load("broken.json")


def route(destination: str, state: str = "active", **target) -> dict:
    return {"DestinationCidrBlock": destination, "State": state, **target}


def table(
    route_table_id: str = "rtb-1",
    vpc_id: str = "vpc-1",
    routes=(),
    subnets=(),
    main: bool = False,
    name: str | None = None,
) -> dict:
    associations = [{"RouteTableId": route_table_id, "Main": True}] if main else []
    associations += [
        {"RouteTableId": route_table_id, "SubnetId": subnet_id, "Main": False}
        for subnet_id in subnets
    ]
    built = {
        "RouteTableId": route_table_id,
        "VpcId": vpc_id,
        "Associations": associations,
        "Routes": list(routes),
    }
    if name:
        built["Tags"] = [{"Key": "Name", "Value": name}]
    return built


def subnet(subnet_id: str, cidr: str = "10.0.1.0/24", public: bool = False, vpc_id="vpc-1") -> dict:
    return {
        "SubnetId": subnet_id,
        "VpcId": vpc_id,
        "CidrBlock": cidr,
        "AvailabilityZone": "eu-central-1a",
        "MapPublicIpOnLaunch": public,
    }


def payload(tables, subnets=(), region: str = "eu-central-1", prefix_lists=None) -> dict:
    built = {"region": region, "route_tables": list(tables), "subnets": list(subnets)}
    if prefix_lists is not None:
        built["prefix_lists"] = list(prefix_lists)
    return built


def prefix_list(prefix_list_id: str, service: str, region: str = "eu-central-1") -> dict:
    return {"PrefixListId": prefix_list_id, "PrefixListName": f"com.amazonaws.{region}.{service}"}


#: The two gateway-endpoint services, as describe_prefix_lists returns them.
SERVICE_LISTS = (prefix_list("pl-s3", "s3"), prefix_list("pl-ddb", "dynamodb"))


def endpoint_route(prefix_list_id: str, state: str = "active", vpce: str = "vpce-1") -> dict:
    return {"DestinationPrefixListId": prefix_list_id, "GatewayId": vpce, "State": state}


def rules(result, route_table_id: str | None = None) -> list[str]:
    """Every rule name in the report, optionally for one route table."""
    return [
        finding["rule"]
        for t in result["tables"]
        if route_table_id in (None, t["route_table_id"])
        for finding in t["findings"]
    ]


def findings_for(result, rule: str) -> list[dict]:
    return [f for t in result["tables"] for f in t["findings"] if f["rule"] == rule]


def table_in(result, route_table_id: str) -> dict:
    return next(t for t in result["tables"] if t["route_table_id"] == route_table_id)
