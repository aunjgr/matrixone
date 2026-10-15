#!/usr/bin/env python3
"""Archive a completed Nsight export before the frozen controller retires it.

This evidence-only launcher changes neither profiling arguments nor collection.
Only `nsys export` waits for an additional, checked archive operation.
"""
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_export(arguments, destination):
    output = Path(arguments[arguments.index("--output") + 1]).resolve()
    report = Path(arguments[-1]).resolve()
    phase = output.parent
    if (output.name != "resource.sqlite" or report.name != "resource.nsys-rep"
            or report.parent != phase or not re.fullmatch(r"phase-[1-6]", phase.name)):
        raise ValueError("unexpected frozen-controller export paths")
    directory = destination / phase.name
    directory.mkdir(mode=0o700)
    paths = [output, report] + sorted((phase / "native").glob("*.log"))
    members = {}
    total = 0
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.resolve() != path:
            raise ValueError("profile archive requires regular, direct files")
        total += info.st_size
        if total > 48 << 30:
            raise ValueError("profile archive exceeds controller phase quota")
        members[path.relative_to(phase).as_posix()] = {
            "sha256": digest(path), "bytes": info.st_size,
        }
    archive = directory / "trace.tar.gz"
    temporary = directory / "trace.tar.gz.partial"
    with temporary.open("xb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=3) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|") as tar:
                for path in paths:
                    info = tar.gettarinfo(str(path), arcname=path.relative_to(phase).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o600
                    with path.open("rb") as source:
                        tar.addfile(info, source)
        raw.flush()
        os.fsync(raw.fileno())
    temporary.rename(archive)
    return {"archive": "trace.tar.gz", "sha256": digest(archive),
            "bytes": archive.stat().st_size, "members": members}


def main():
    real = Path(os.environ.get("NSYS_ARCHIVE_REAL", "/usr/bin/nsys")).resolve()
    if real == Path(__file__).resolve():
        raise ValueError("recursive Nsight launcher")
    arguments = sys.argv[1:]
    if not arguments or arguments[0] != "export":
        os.execv(str(real), [str(real), *arguments])
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = subprocess.run([str(real), *arguments], check=False)
    if result.returncode:
        return result.returncode if result.returncode > 0 else 128 - result.returncode
    destination = Path(os.environ["NSYS_ARCHIVE_DIRECTORY"]).resolve()
    receipt = archive_export(arguments, destination)
    receipt.update(command=[str(real), *arguments], started_at=started,
                   completed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   export_exit_status=0, archive_complete=True,
                   launcher_sha256=digest(Path(__file__).resolve()))
    phase = Path(arguments[arguments.index("--output") + 1]).parent.name
    (destination / phase / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print("profile evidence archive failed: " + type(error).__name__, file=sys.stderr)
        sys.exit(74)
