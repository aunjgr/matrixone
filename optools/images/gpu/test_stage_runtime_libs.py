#!/usr/bin/env python3
# Copyright 2026 Matrix Origin
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contract tests for collision-safe, driver-free Pixi library staging."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("stage-runtime-libs.sh")


class RuntimeLibraryStagingTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mo-gpu-runtime-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "pixi"
        self.top_lib = self.prefix / "lib"
        self.cuda_lib = self.prefix / "targets/x86_64-linux/lib"
        self.top_lib.mkdir(parents=True)
        self.cuda_lib.mkdir(parents=True)
        self.runtime = self.root / "runtime"

    def stage(self):
        return subprocess.run(
            ["sh", str(SCRIPT), str(self.prefix), str(self.runtime)],
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_cuda_cross_directory_symlinks_become_valid_hardlinks(self):
        real = self.cuda_lib / "libcudart.so.13.3.29"
        real.write_bytes(b"CUDA runtime")
        (self.top_lib / real.name).symlink_to(
            f"../targets/x86_64-linux/lib/{real.name}"
        )
        (self.top_lib / "libcudart.so").symlink_to(real.name)
        (self.cuda_lib / "libcudart.so.13").symlink_to(real.name)

        result = self.stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("libcudart.so", "libcudart.so.13", real.name):
            staged = self.runtime / name
            self.assertTrue(staged.is_file(), name)
            self.assertFalse(staged.is_symlink(), name)
            self.assertEqual(staged.read_bytes(), b"CUDA runtime")
        self.assertEqual(
            (self.runtime / "libcudart.so").stat().st_ino,
            (self.runtime / real.name).stat().st_ino,
        )

    def test_different_bytes_with_one_basename_are_rejected(self):
        (self.top_lib / "libcollision.so").write_bytes(b"first")
        (self.cuda_lib / "libcollision.so").write_bytes(b"second")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("conflicting Pixi runtime library basename", result.stderr)
        self.assertEqual((self.runtime / "libcollision.so").read_bytes(), b"first")

    def test_dangling_symlink_is_rejected(self):
        (self.cuda_lib / "libgood.so").write_bytes(b"good")
        (self.top_lib / "libmissing.so").symlink_to("missing.so")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dangling Pixi runtime library", result.stderr)

    def test_driver_stub_alias_is_rejected(self):
        stub = self.cuda_lib / "stubs/libcuda.so"
        stub.parent.mkdir()
        stub.write_bytes(b"stub")
        (self.top_lib / "libalias.so").symlink_to(
            "../targets/x86_64-linux/lib/stubs/libcuda.so"
        )
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("driver stub", result.stderr)

    def test_outside_prefix_alias_is_rejected(self):
        outside = self.root / "outside.so"
        outside.write_bytes(b"outside")
        (self.top_lib / "liboutside.so").symlink_to(outside)
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes its prefix", result.stderr)

    def test_destination_must_be_empty(self):
        (self.top_lib / "libgood.so").write_bytes(b"good")
        self.runtime.mkdir()
        (self.runtime / "old.so").write_bytes(b"old")
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be empty", result.stderr)


if __name__ == "__main__":
    unittest.main()
