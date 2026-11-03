"""Output formats stay machine-readable and name the offending route table."""

from __future__ import annotations

import json

import pytest
from conftest import payload

from aws_route_table_audit.analyze import analyze
from aws_route_table_audit.render import render, render_json, render_markdown, render_text


def test_text_lists_every_finding_with_its_table(broken):
    output = render_text(analyze(broken))
    assert "region=eu-central-1" in output
    assert "nat-0deadbeef" in output
    assert "rtb-0bad-workers" in output
    assert "critical" in output
    assert output.rstrip().endswith("worst: critical.")


def test_text_marks_the_main_table_and_clean_tables(clean):
    output = render_text(analyze(clean))
    assert "[main]" in output
    assert "clean" in output
    assert "0 critical" in output


def test_text_columns_are_aligned(broken):
    lines = render_text(analyze(broken)).splitlines()
    header = next(line for line in lines if line.startswith("SEVERITY"))
    table_start = header.index("ROUTE TABLE")
    rows = [line for line in lines if line.startswith(("critical ", "warn ", "ok "))]
    assert rows
    assert all(line[table_start:].startswith("rtb-") for line in rows)


def test_text_wraps_long_messages_under_the_column(broken):
    output = render_text(analyze(broken), width=90)
    assert all(len(line) <= 120 for line in output.splitlines())


def test_text_handles_an_empty_scope():
    assert "no route tables in scope" in render_text(analyze(payload([])))


def test_json_round_trips(broken):
    parsed = json.loads(render_json(analyze(broken)))
    assert parsed["region"] == "eu-central-1"
    criticals = [t for t in parsed["tables"] if t["severity"] == "critical"]
    assert len(criticals) == 3
    assert all("findings" in t for t in parsed["tables"])


def test_markdown_is_a_table_with_one_row_per_finding(broken):
    report = analyze(broken)
    output = render_markdown(report)
    assert output.startswith("### aws-route-table-audit: `eu-central-1`")
    assert "| Severity | Route table | Rule | Finding |" in output
    rows = [line for line in output.splitlines() if line.startswith("| critical")]
    assert len(rows) == report["summary"]["findings_by_severity"]["critical"]
    assert "`blackhole-route`" in output


def test_markdown_says_so_when_there_is_nothing_to_report(clean):
    output = render_markdown(analyze(clean))
    assert "No findings across 2 route tables." in output
    assert "| Severity" not in output


def test_markdown_escapes_pipes_in_messages():
    report = {
        "region": "eu-central-1",
        "tables": [
            {
                "route_table_id": "rtb-1",
                "vpc_id": "vpc-1",
                "name": "",
                "main": False,
                "severity": "warn",
                "findings": [{"rule": "demo", "severity": "warn", "message": "a | b"}],
            }
        ],
        "summary": {
            "tables": 1,
            "findings": 1,
            "severity": "warn",
            "tables_by_severity": {"ok": 0, "warn": 1, "critical": 0},
            "findings_by_severity": {"ok": 0, "warn": 1, "critical": 0},
        },
    }
    assert "a \\| b" in render_markdown(report)


@pytest.mark.parametrize("output_format", ["text", "json", "markdown"])
def test_render_dispatch(output_format, broken):
    assert render(analyze(broken), output_format).strip()
