import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.phase = self.root / "campaign" / "phase-1"
        self.phase.mkdir(parents=True)
        self.archive = self.root / "archives"
        self.archive.mkdir()
        self.real = self.root / "real-nsys"
        self.real.write_text("#!/usr/bin/env python3\n"
            "import json,os,sys\nfrom pathlib import Path\n"
            "if sys.argv[1]=='export':\n"
            " p=Path(sys.argv[sys.argv.index('--output')+1]);p.write_bytes(b'sqlite-evidence')\n"
            " Path(sys.argv[-1]).write_bytes(b'completed-profile')\n"
            "sys.stdout.write(json.dumps(sys.argv[1:]))\n"
            "sys.exit(int(os.environ.get('FAKE_EXIT','0')))\n")
        self.real.chmod(0o700)
        self.launcher = Path(__file__).with_name("nsys_archive.py")

    def invoke(self, arguments=None, **environment):
        arguments = arguments or ["export", "--type=sqlite", "--ts-normalize=true",
            "--output", str(self.phase / "resource.sqlite"),
            str(self.phase / "resource.nsys-rep")]
        return subprocess.run([sys.executable, str(self.launcher), *arguments],
            env=dict(os.environ, NSYS_ARCHIVE_REAL=str(self.real),
                     NSYS_ARCHIVE_DIRECTORY=str(self.archive), **environment),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_export_is_archived_before_launcher_returns(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads((self.archive / "phase-1/receipt.json").read_text())
        self.assertTrue(receipt["archive_complete"])
        self.assertEqual(receipt["export_exit_status"], 0)
        with tarfile.open(self.archive / "phase-1/trace.tar.gz", "r:gz") as archive:
            self.assertEqual(archive.extractfile("resource.sqlite").read(), b"sqlite-evidence")
            self.assertEqual(archive.extractfile("resource.nsys-rep").read(), b"completed-profile")

    def test_export_failure_propagates_without_archive(self):
        self.assertEqual(self.invoke(FAKE_EXIT="17").returncode, 17)
        self.assertEqual(list(self.archive.iterdir()), [])

    def test_archive_failure_fails_export_and_keeps_raw_input(self):
        (self.archive / "phase-1").write_text("collision")
        result = self.invoke()
        self.assertEqual(result.returncode, 74)
        self.assertEqual((self.phase / "resource.sqlite").read_bytes(), b"sqlite-evidence")
        self.assertFalse((self.archive / "phase-1/receipt.json").exists())

    def test_other_nsight_commands_are_passed_through(self):
        result = self.invoke(["profile", "--example=value"], FAKE_EXIT="19")
        self.assertEqual(result.returncode, 19)
        self.assertEqual(json.loads(result.stdout), ["profile", "--example=value"])
        self.assertEqual(list(self.archive.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
