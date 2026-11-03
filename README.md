# aws-route-table-audit
Audits every VPC route table for the routes that silently break connectivity: blackholed routes, subnets implicitly on the main table, missing or duplicated default routes, shadowed overlapping CIDRs, and private subnets routed straight at an internet gateway.
