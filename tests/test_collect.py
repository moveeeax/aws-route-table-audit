"""The collector against a fake EC2 client: which calls it makes and what it keeps."""

from __future__ import annotations

import sys
import types

import pytest
from botocore.exceptions import ClientError

from aws_route_table_audit.collect import collect


class FakePaginator:
    def __init__(self, client, operation):
        self.client, self.operation = client, operation

    def paginate(self, **kwargs):
        self.client.calls.append((self.operation, kwargs))
        result = self.client.responses[self.operation]
        if isinstance(result, Exception):
            raise result
        yield from result


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get_paginator(self, operation):
        return FakePaginator(self, operation)


def _install(monkeypatch, client):
    class Session:
        def __init__(self, profile_name=None, region_name=None):
            self.region_name = region_name

        def client(self, name):
            assert name == "ec2"
            return client

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(Session=Session))


def _denied(code):
    return ClientError({"Error": {"Code": code, "Message": "no"}}, "DescribePrefixLists")


def _responses(prefix_lists):
    return {
        "describe_route_tables": [{"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1"}]}],
        "describe_subnets": [{"Subnets": []}],
        "describe_prefix_lists": prefix_lists,
    }


def test_prefix_lists_are_collected_unfiltered(monkeypatch):
    s3 = {"PrefixListId": "pl-1", "PrefixListName": "com.amazonaws.eu-central-1.s3"}
    client = FakeClient(_responses([{"PrefixLists": [s3]}, {"PrefixLists": []}]))
    _install(monkeypatch, client)
    payload = collect(region="eu-central-1", vpc_id="vpc-1")
    assert payload["prefix_lists"] == [s3]
    calls = dict(client.calls)
    assert calls["describe_route_tables"] == {"Filters": [{"Name": "vpc-id", "Values": ["vpc-1"]}]}
    assert calls["describe_prefix_lists"] == {}


def test_denied_prefix_lists_leave_a_null_instead_of_failing(monkeypatch):
    _install(monkeypatch, FakeClient(_responses(_denied("UnauthorizedOperation"))))
    payload = collect(region="eu-central-1")
    assert payload["prefix_lists"] is None
    assert payload["route_tables"]


def test_other_prefix_list_errors_still_fail(monkeypatch):
    _install(monkeypatch, FakeClient(_responses(_denied("RequestLimitExceeded"))))
    with pytest.raises(ClientError):
        collect(region="eu-central-1")
