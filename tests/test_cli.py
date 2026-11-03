"""End-to-end CLI behaviour, including the exit codes CI depends on."""

from __future__ import annotations

import json

import pytest
from conftest import FIXTURES

from aws_route_table_audit.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_fail_on_critical_exits_1_for_a_broken_vpc(capsys):
    broken = str(FIXTURES / "broken.json")
    code, out, _ = run(capsys, "--from-json", broken, "--fail-on", "critical")
    assert code == 1
    assert "nat-0deadbeef" in out


def test_fail_on_critical_exits_0_for_a_clean_vpc(capsys):
    code, out, _ = run(capsys, "--from-json", str(FIXTURES / "clean.json"), "--fail-on", "critical")
    assert code == 0
    assert "0 critical" in out


def test_fail_on_none_never_fails(capsys):
    code, _, _ = run(capsys, "--from-json", str(FIXTURES / "broken.json"), "--fail-on", "none")
    assert code == 0


def test_json_output_is_parseable(capsys):
    code, out, _ = run(capsys, "--from-json", str(FIXTURES / "broken.json"), "--format", "json")
    assert code == 1
    report = json.loads(out)
    assert [t["route_table_id"] for t in report["tables"] if t["severity"] == "critical"]


def test_markdown_output(capsys):
    _, out, _ = run(capsys, "--from-json", str(FIXTURES / "broken.json"), "--format", "markdown")
    assert out.startswith("### aws-route-table-audit")


def test_missing_file_exits_2_without_a_traceback(capsys, tmp_path):
    code, out, err = run(capsys, "--from-json", str(tmp_path / "nope.json"))
    assert code == 2
    assert out == ""
    assert "cannot read" in err
    assert "Traceback" not in err


def test_invalid_json_exits_2(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(bad))
    assert code == 2
    assert "not valid JSON" in err


def test_json_that_is_not_a_payload_exits_2(capsys, tmp_path):
    bad = tmp_path / "wrong.json"
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(bad))
    assert code == 2
    assert "route_tables" in err


def test_save_json_writes_a_replayable_payload(capsys, tmp_path):
    out_path = tmp_path / "saved.json"
    code, _, _ = run(
        capsys,
        "--from-json",
        str(FIXTURES / "broken.json"),
        "--save-json",
        str(out_path),
        "--format",
        "json",
    )
    assert code == 1
    replayed = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(replayed["route_tables"]) == 4

    code_again, _, _ = run(capsys, "--from-json", str(out_path), "--format", "json")
    assert code_again == 1


def test_examples_payload_is_valid(capsys):
    example = FIXTURES.parent.parent / "examples" / "prod.json"
    code, out, _ = run(
        capsys, "--from-json", str(example), "--format", "json", "--fail-on", "none"
    )
    assert code == 0
    report = json.loads(out)
    assert report["summary"]["findings"] > 0


def test_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "aws-route-table-audit" in capsys.readouterr().out


def test_collect_is_not_imported_when_replaying(capsys, monkeypatch):
    """--from-json must never need boto3 installed."""
    monkeypatch.delitem(__import__("sys").modules, "boto3", raising=False)
    code, _, _ = run(capsys, "--from-json", str(FIXTURES / "clean.json"))
    assert code == 0
