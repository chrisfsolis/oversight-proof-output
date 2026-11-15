# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Oversight Proof LLC
# Licensed under the Apache License, Version 2.0. See the LICENSE file in this repository, or
# http://www.apache.org/licenses/LICENSE-2.0
"""CALLS CODE. ``verify.py`` checked as a recipient runs it: stock Python, one child process each.

Run from the top of the repository, with nothing installed:

    python -m unittest discover -s tests -v

The verifier under test is ``verify.py`` at the top of the repository, or whatever ``VERIFY_PY``
names. The kits are built from ``examples/kit/reference_packet`` in a temporary folder per test.

* The published kit passes, with and without the root it was published with.
* One changed byte fails, naming the file.
* A command line the verifier cannot read exits 2 and checks nothing.
* Every hostile kit in ``kitcases.CASES`` fails closed: exit 1, a FAIL headline, one line per
  reason, the reason named, no traceback, and the kit's files exactly as they were.

Every case must fail closed; none is marked as expected to fail.

Deterministic: every kit is built from committed bytes and literals; nothing is timed.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kitcases  # noqa: E402

# The root the reference kit records for itself. Read from the committed kit rather than written
# here, so regenerating the kit moves no second copy of it (the README carries the published one);
# the verifier recomputes the root from the bytes and must arrive at this value.
PUBLISHED_ROOT: str = json.loads((kitcases.reference_kit() / "provenance.json").read_bytes())[
    "expected_manifest_root_hash"
]


class _KitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp(prefix="verify-test-"))
        self.addCleanup(shutil.rmtree, self.base, True)


class PublishedKit(_KitTest):
    def test_the_reference_kit_passes(self) -> None:
        result = kitcases.run(kitcases.fresh_kit(self.base))
        self.assertEqual(result.code, kitcases.EXIT_PASS, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("PASS (internally consistent): "), result.stdout)
        self.assertIn(f"  root: {PUBLISHED_ROOT}", result.stdout.splitlines())
        self.assertIn("  files checked: 75", result.stdout.splitlines())

    def test_the_reference_kit_passes_against_its_published_root(self) -> None:
        kit = kitcases.fresh_kit(self.base)
        result = kitcases.run(kit, "--expect-root", PUBLISHED_ROOT)
        self.assertEqual(result.code, kitcases.EXIT_PASS, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("PASS: every file matches the manifest, and "))

    def test_the_recorded_root_is_a_sha256(self) -> None:
        self.assertRegex(PUBLISHED_ROOT, r"^[0-9a-f]{64}$")

    def test_json_output_is_one_document_carrying_the_root(self) -> None:
        result = kitcases.run(kitcases.fresh_kit(self.base), "--json")
        self.assertEqual(result.code, kitcases.EXIT_PASS)
        document = json.loads(result.stdout)
        self.assertIs(document["ok"], True)
        self.assertEqual(document["recomputed_root"], PUBLISHED_ROOT)

    def test_a_different_supplied_root_fails_naming_both(self) -> None:
        other = "0" * 64
        result = kitcases.run(kitcases.fresh_kit(self.base), "--expect-root", other)
        self.assertEqual(result.code, kitcases.EXIT_FAIL)
        self.assertIn(f"supplied {other}", result.stdout)
        self.assertIn(f"recomputed {PUBLISHED_ROOT}", result.stdout)


class OneChangedByte(_KitTest):
    def test_one_changed_byte_fails_naming_the_file(self) -> None:
        kit = kitcases.build("one_changed_byte", self.base)
        result = kitcases.run(kit)
        self.assertEqual(result.code, kitcases.EXIT_FAIL, result.stdout + result.stderr)
        self.assertIn(
            "  - content changed: audit-consistency/run_manifest.json", result.stdout.splitlines()
        )


class CommandLine(_KitTest):
    def test_a_command_line_it_cannot_read_exits_2(self) -> None:
        kit = kitcases.fresh_kit(self.base)
        for args in (["--expect-root", "not-hex"], ["--no-such-option"], [str(kit)]):
            with self.subTest(args=args):
                result = kitcases.run(kit, *args)
                self.assertEqual(result.code, kitcases.EXIT_USAGE, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)


class HostileKits(_KitTest):
    """One test per case in ``kitcases.CASES``, added below."""


def _hostile_test(name: str) -> Callable[[HostileKits], None]:
    case = kitcases.CASES[name]

    def test(self: HostileKits) -> None:
        if case.needs == "symlink" and not kitcases.can_symlink(self.base):
            self.skipTest("this machine does not let an ordinary user create a symlink")
        if case.needs == "junction" and sys.platform != "win32":
            self.skipTest("junctions exist only on Windows")
        kit = kitcases.build(name, self.base)
        before = kitcases.tree(self.base)
        result = kitcases.run(kit, console=case.console)
        self.assertEqual(kitcases.fail_closed_problems(result, case.reason), [])
        self.assertEqual(kitcases.tree(self.base), before, "the verifier changed the kit")

    test.__name__ = f"test_{name}"
    test.__doc__ = f"D1{case.item}: {name.replace('_', ' ')}."
    return test


for _name in kitcases.CASES:
    setattr(HostileKits, f"test_{_name}", _hostile_test(_name))


if __name__ == "__main__":
    unittest.main()
