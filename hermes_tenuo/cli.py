"""
hermes-tenuo CLI — warrant minting and management.

Usage:
    hermes-tenuo mint --ttl 1h --allow read_file:path=/data --allow web_search
    hermes-tenuo status
"""

from __future__ import annotations

import argparse
import sys


def cmd_mint(args: argparse.Namespace) -> int:
    """Mint a warrant via Tenuo Cloud and print base64 to stdout."""
    # TODO: implement Cloud-backed minting once endpoint is available
    print(
        "error: hermes-tenuo mint requires Tenuo Cloud. "
        "Set TENUO_CONNECT_TOKEN and ensure Cloud mint API is enabled.",
        file=sys.stderr,
    )
    return 1


def cmd_status(args: argparse.Namespace) -> int:
    """Show current plugin configuration status."""
    import os

    token = os.environ.get("TENUO_CONNECT_TOKEN")
    warrant = os.environ.get("TENUO_WARRANT")
    signing_key = os.environ.get("TENUO_SIGNING_KEY")

    print(f"TENUO_CONNECT_TOKEN : {'set' if token else 'not set'}")
    print(f"TENUO_WARRANT       : {'set' if warrant else 'not set (audit-only)'}")
    print(f"TENUO_SIGNING_KEY   : {'set' if signing_key else 'not set'}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hermes-tenuo",
        description="Tenuo authorization plugin for Hermes Agent",
    )
    subparsers = parser.add_subparsers(dest="command")

    mint_parser = subparsers.add_parser("mint", help="Mint a warrant via Tenuo Cloud")
    mint_parser.add_argument("--ttl", default="1h", help="Warrant TTL (e.g. 1h, 30m)")
    mint_parser.add_argument(
        "--allow",
        action="append",
        dest="capabilities",
        metavar="TOOL[:ARG=VALUE]",
        help="Add a capability (e.g. read_file:path=/data)",
    )
    mint_parser.add_argument("--connect-token", help="Tenuo Cloud connect token")

    subparsers.add_parser("status", help="Show configuration status")

    args = parser.parse_args()

    if args.command == "mint":
        sys.exit(cmd_mint(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
