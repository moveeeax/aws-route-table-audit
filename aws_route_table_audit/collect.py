"""The only part of the tool that talks to AWS.

It makes three describe calls and returns plain dicts, so the payload it produces can
be saved with ``--save-json`` and replayed later with ``--from-json``.
"""

from __future__ import annotations

REQUIRED_CALLS = ("describe_route_tables", "describe_subnets")
#: Feeds the ``missing-gateway-endpoint`` rule. A role without ``ec2:DescribePrefixLists``
#: still gets the other rules: the payload carries ``prefix_lists: null`` instead.
OPTIONAL_CALLS = ("describe_prefix_lists",)


def _paginate(client, operation: str, key: str, filters: list[dict]) -> list[dict]:
    paginator = client.get_paginator(operation)
    kwargs = {"Filters": filters} if filters else {}
    items: list[dict] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key) or [])
    return items


def _prefix_lists(client) -> list[dict] | None:
    """AWS service prefix lists for the region, ``None`` when the call is not allowed.

    Unfiltered: the region returns only a handful, and the rule engine picks the S3 and
    DynamoDB ones by name, which keeps the China ``cn.com.amazonaws.`` names working.
    """
    from botocore.exceptions import ClientError

    try:
        return _paginate(client, "describe_prefix_lists", "PrefixLists", [])
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "UnauthorizedOperation":
            return None
        raise


def collect(region: str | None = None, vpc_id: str | None = None, profile: str | None = None):
    """Collect route tables, subnets and service prefix lists for one region."""
    import boto3  # imported lazily: the rule engine and its tests need no boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("ec2")
    filters = [{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
    return {
        "region": session.region_name or region,
        "route_tables": _paginate(client, "describe_route_tables", "RouteTables", filters),
        "subnets": _paginate(client, "describe_subnets", "Subnets", filters),
        "prefix_lists": _prefix_lists(client),
    }
