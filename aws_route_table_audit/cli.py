"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from aws_route_table_audit import __version__
from aws_route_table_audit.analyze import PayloadError, analyze, exit_code
from aws_route_table_audit.render import RENDERERS, render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-route-table-audit",
        description="Find blackholed routes, implicit main-table subnets, missing or "
        "duplicated default routes, shadowed CIDRs, private subnets routed at an "
        "internet gateway and NAT-routed tables without S3/DynamoDB gateway endpoints.",
    )
    parser.add_argument("--region", help="AWS region (defaults to the session region)")
    parser.add_argument("--vpc-id", help="restrict the audit to one VPC")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=sorted(RENDERERS),
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("warn", "critical", "none"),
        default="critical",
        help="severity that makes the exit code 1 (default: critical)",
    )
    parser.add_argument(
        "--from-json",
        metavar="PATH",
        help="replay a saved payload instead of calling AWS",
    )
    parser.add_argument(
        "--save-json",
        metavar="PATH",
        help="write the collected payload so it can be replayed with --from-json",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _load_payload(path: str):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as error:
        raise PayloadError(f"cannot read {path}: {error.strerror or error}") from error
    except json.JSONDecodeError as error:
        raise PayloadError(f"{path} is not valid JSON: {error}") from error


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.from_json:
        try:
            payload = _load_payload(args.from_json)
        except PayloadError as error:
            print(f"aws-route-table-audit: {error}", file=sys.stderr)
            return EXIT_USAGE
    else:
        from aws_route_table_audit.collect import collect

        try:
            payload = collect(region=args.region, vpc_id=args.vpc_id, profile=args.profile)
        except Exception as error:  # noqa: BLE001 - surface AWS errors without a traceback
            print(f"aws-route-table-audit: AWS call failed: {error}", file=sys.stderr)
            return EXIT_USAGE

    try:
        report = analyze(payload)
    except PayloadError as error:
        print(f"aws-route-table-audit: {error}", file=sys.stderr)
        return EXIT_USAGE
    for rule, reason in report["skipped_rules"].items():
        print(f"aws-route-table-audit: {rule} skipped: {reason}", file=sys.stderr)

    if args.save_json:
        try:
            with open(args.save_json, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
        except OSError as error:
            print(f"aws-route-table-audit: cannot write {args.save_json}: {error}", file=sys.stderr)
            return EXIT_USAGE

    sys.stdout.write(render(report, args.output_format))
    return exit_code(report, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
