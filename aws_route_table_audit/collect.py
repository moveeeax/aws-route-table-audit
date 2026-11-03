"""The only part of the tool that talks to AWS.

It makes two describe calls and returns plain dicts, so the payload it produces can
be saved with ``--save-json`` and replayed later with ``--from-json``.
"""

from __future__ import annotations

REQUIRED_CALLS = ("describe_route_tables", "describe_subnets")


def _paginate(client, operation: str, key: str, filters: list[dict]) -> list[dict]:
    paginator = client.get_paginator(operation)
    kwargs = {"Filters": filters} if filters else {}
    items: list[dict] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key) or [])
    return items


def collect(region: str | None = None, vpc_id: str | None = None, profile: str | None = None):
    """Collect route tables and subnets for one region, optionally one VPC."""
    import boto3  # imported lazily: the rule engine and its tests need no boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("ec2")
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
    return {
        "region": session.region_name or region,
        "route_tables": _paginate(client, "describe_route_tables", "RouteTables", filters),
        "subnets": _paginate(client, "describe_subnets", "Subnets", filters),
    }
