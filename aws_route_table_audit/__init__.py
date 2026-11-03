"""Audit AWS VPC route tables for routes that silently break connectivity."""

from aws_route_table_audit.analyze import PayloadError, analyze

__all__ = ["PayloadError", "__version__", "analyze"]
__version__ = "0.1.0"
