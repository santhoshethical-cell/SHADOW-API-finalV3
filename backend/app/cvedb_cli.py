"""Command-line management of the local CVE database.

    python3 run.py cvedb status
    python3 run.py cvedb update [--full] [--product vendor:product ...]
    python3 run.py cvedb import FILE [FILE ...] [--complete-for vendor:product ...]

(``run.py cvedb`` runs ``python -m app.cvedb_cli`` inside the project venv.)
The NVD API key is read from ``SAS_NVD_API_KEY``; it is never printed.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from app import cvedb
from app.secrets_guard import install_log_filter, scrub


def _pair(text: str) -> tuple[str, str]:
    parts = text.strip().lower().split(":")
    if len(parts) != 2 or not all(parts):
        raise argparse.ArgumentTypeError("expected vendor:product, e.g. jquery:jquery")
    return parts[0], parts[1]


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")
    install_log_filter()
    ap = argparse.ArgumentParser(prog="cvedb", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", type=Path, help="database path (default: data/cvedb.sqlite3)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="show database state and per-component coverage")
    up = sub.add_parser("update", help="download from the NVD CVE API 2.0")
    up.add_argument("--full", action="store_true",
                    help="re-download everything instead of incremental changes")
    up.add_argument("--product", type=_pair, action="append",
                    help="limit to vendor:product (repeatable); default: whole catalog")
    im = sub.add_parser("import", help="import NVD CVE API 2.0 JSON files (offline)")
    im.add_argument("files", nargs="+", type=Path)
    im.add_argument("--complete-for", type=_pair, action="append", default=[],
                    help="declare the files contain ALL CVEs for vendor:product")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "status":
            print(json.dumps(cvedb.status(args.db), indent=2))
            return 0
        if args.cmd == "update":
            res = cvedb.update_from_nvd(args.db, mode="full" if args.full else "incremental",
                                        pairs=args.product, progress=print)
        else:
            res = cvedb.import_files(args.files, args.db, complete_for=args.complete_for)
        print(json.dumps(res, indent=2))
        return 0
    except Exception as exc:   # report cleanly; the previous DB is untouched
        print(f"CVE database {args.cmd} failed: {scrub(str(exc))}", file=sys.stderr)
        print("The previous database (if any) was kept unchanged.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
