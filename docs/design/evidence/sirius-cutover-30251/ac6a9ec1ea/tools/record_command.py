#!/usr/bin/env python3
"""Retain actual command status and hashed output; never reconstruct old exits."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, required=True)
    parser.add_argument("--env", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    environment = os.environ.copy()
    selected = dict(value.split("=", 1) for value in args.env)
    environment.update(selected)
    receipt = {"command": command, "cwd": str(args.cwd.resolve()),
               "environment_overrides": selected,
               "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    with args.log.open("xb") as output:
        result = subprocess.run(command, cwd=args.cwd, env=environment,
                                stdout=output, stderr=subprocess.STDOUT, check=False)
    with args.log.open("rb") as output:
        receipt.update(exit_status=result.returncode,
                       completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       output_sha256=hashlib.file_digest(output, "sha256").hexdigest(),
                       output_file=args.log.name)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)


if __name__ == "__main__":
    main()
