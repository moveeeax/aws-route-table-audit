# aws-route-table-audit

[![ci](https://github.com/moveeeax/aws-route-table-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-route-table-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A route table is the one piece of AWS networking that fails without complaining. A NAT
gateway gets replaced, the route that pointed at it turns into a blackhole, and the table
still looks like a table: same CIDR, same row, just a target that no longer exists. Nothing
alarms. This tool puts every broken and every accidental route in one list and exits
non-zero in CI.

## What it checks

| Rule | Severity | What it means |
| --- | --- | --- |
| `blackhole-route` | critical | A route whose `State` is `blackhole`. Reported with its destination and the dead gateway, NAT, peering or ENI id. |
| `private-subnet-via-igw` | critical | An associated subnet with `MapPublicIpOnLaunch: false` whose default route points at an internet gateway. |
| `implicit-main-association` | warn / critical | A subnet with no association of its own, silently inheriting the VPC main route table. Critical when that table defaults to an internet gateway and the subnet is not auto-assign-public. |
| `no-default-route` | warn | No `0.0.0.0/0` route at all, so anything outside the local CIDR is dropped. |
| `duplicate-default-route` | warn | More than one live default route competing for `0.0.0.0/0`, e.g. an igw and a NAT. |
| `shadowed-overlap` | warn | Two routes in one table where one CIDR contains the other. Names the longest-prefix winner, so a shadowed route is not mistaken for an active one. |
| `missing-gateway-endpoint` | warn | A table whose live `0.0.0.0/0` route points at a NAT gateway but has no route to the S3 or DynamoDB prefix list (`com.amazonaws.<region>.s3` / `.dynamodb`). That traffic still works, it just pays NAT per-GB processing that a free gateway endpoint would not. One finding per missing service. |

A default route next to specific routes is how routing is supposed to work, so `0.0.0.0/0`
and `::/0` are never treated as the shadowing supernet.

`missing-gateway-endpoint` needs the region's prefix lists in the payload. A payload saved
by an older version, or a run where `ec2:DescribePrefixLists` was denied, skips that rule
and says so on stderr and under `skipped_rules` in the JSON report; the other rules run as
before.

Tables are sorted worst-finding first, and the exit code is driven by `--fail-on`.

## How it works

Three API calls: `describe_route_tables` and `describe_subnets`, both filterable by
`--vpc-id`, and an unfiltered `describe_prefix_lists` that maps the S3 and DynamoDB
prefix list ids of the region. The collector returns plain dicts and the rule engine
consumes them, which means two useful things. Associations get joined properly — explicit subnet associations,
the main table, and the subnets that reach the main table only because nobody associated
them — and every rule is testable without AWS credentials. `--save-json` writes the
payload, `--from-json` replays it. CIDR containment is `ipaddress` from the standard
library; `boto3` is the only runtime dependency and it is imported lazily, so a replay run
does not need it installed.

## Install

```bash
pip install git+https://github.com/moveeeax/aws-route-table-audit.git
```

Or from a clone, for development:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest
```

## Usage

```bash
aws-route-table-audit --region eu-central-1
aws-route-table-audit --vpc-id vpc-0abc123 --fail-on critical
aws-route-table-audit --format json | jq '.tables[] | select(.severity=="critical")'
aws-route-table-audit --from-json examples/prod.json --format markdown
```

Against the payload bundled in `examples/`:

```console
$ aws-route-table-audit --from-json examples/prod.json
aws-route-table-audit  region=eu-central-1  tables=4

SEVERITY  ROUTE TABLE                         VPC        FINDING
-------------------------------------------------------------------------------------------------
critical  rtb-0a1public (prod-public) [main]  vpc-0prod  subnet subnet-0workers-c (10.20.30.0/24)
                                                         has no route table association, so it
                                                         inherits main table rtb-0a1public, which
                                                         defaults to internet gateway igw-0prod; the
                                                         subnet does not auto-assign public IPs and
                                                         was meant to be private
critical  rtb-0b2private-a (prod-private-1a)  vpc-0prod  route to 0.0.0.0/0 is blackholed: nat
                                                         gateway nat-0retired no longer exists
warn      rtb-0b2private-a (prod-private-1a)  vpc-0prod  10.90.0.0/16 (via peering connection
                                                         pcx-0analytics) overlaps 10.90.7.0/24 (via
                                                         transit gateway tgw-0hub); 10.90.7.0/24
                                                         wins by longest-prefix match for addresses
                                                         inside it
warn      rtb-0c3private-b (prod-private-1b)  vpc-0prod  no gateway endpoint route for DynamoDB
                                                         (pl-0ddb,
                                                         com.amazonaws.eu-central-1.dynamodb): its
                                                         traffic goes through nat gateway
                                                         nat-0prod-1b and pays NAT data processing
warn      rtb-0d4data (prod-data)             vpc-0prod  no 0.0.0.0/0 route: anything not matching a
                                                         local route is dropped

5 findings: 2 critical, 3 warn. worst: critical.
$ echo $?
1
```

### Flags

| Flag | Default | Notes |
| --- | --- | --- |
| `--region` | session region | Passed to the boto3 session. |
| `--vpc-id` | all VPCs | Becomes a `vpc-id` filter on both describe calls. |
| `--profile` | default credentials | Named AWS profile. |
| `--format` | `text` | `text`, `json` or `markdown`. |
| `--fail-on` | `critical` | `warn`, `critical` or `none`. |
| `--from-json` | — | Replay a saved payload, no AWS calls. |
| `--save-json` | — | Write the collected payload for later replay. |

Exit codes: `0` clean (or below the threshold), `1` findings at or above `--fail-on`,
`2` a bad `--from-json` file or a failed AWS call — a message on stderr, never a traceback.

## In CI

```yaml
- name: Audit route tables
  run: aws-route-table-audit --region eu-central-1 --fail-on critical --format markdown
```

Blackholes and private subnets wired to an internet gateway break the build; the warn-level
rules only show up in the log until you raise `--fail-on` to `warn`.

## Permissions

`ec2:DescribeRouteTables`, `ec2:DescribeSubnets` and `ec2:DescribePrefixLists`. Nothing is
written, so a read-only role is enough. Without `ec2:DescribePrefixLists` the run still
succeeds and only `missing-gateway-endpoint` is skipped.

## License

MIT
