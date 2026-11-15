# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Oversight Proof LLC
# Licensed under the Apache License, Version 2.0. See the LICENSE file in this repository, or
# http://www.apache.org/licenses/LICENSE-2.0
"""Coverage-guided fuzzing of ``verify.py`` with Atheris.

The unit tests (``tests/``) need nothing but stock Python; this one file needs Atheris, which is
why it lives apart from them, runs only in ``.github/workflows/fuzz.yml`` (weekly, Linux, Python
3.13, time-limited), and installs its one dependency pinned by hash from ``fuzz/requirements.txt``.

Each input drives the same edits the seeded tests use (``tests/kitcases.py``'s ``mutate``) on a
fresh copy of ``examples/kit/reference_packet``, choosing every edit from the fuzzer's bytes so its
coverage feedback steers which edits are tried; on some inputs the rest of the bytes replace the
integrity manifest outright, so the JSON reader itself is explored. The verifier is then run in
this process and held to the same rules as every other test (``kitcases.violations``):

  a. no PASS unless the bytes match the manifest and both roots;
  b. nothing opened, and no folder listed, outside the kit;
  c. nothing written, created or deleted, and no network use;
  e. exit 0 or 1 with one line per reason, nothing escaping, no PASS on a kit read two ways.

A broken rule raises, which Atheris reports as a crash and saves as a reproducer.

    pip install --require-hashes --only-binary :all: -r fuzz/requirements.txt
    python fuzz/fuzz_verify.py -max_total_time=600
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

# Atheris's stubs (types-atheris) are not installed here: they would be a dependency of their own.
import atheris  # type: ignore[import-untyped]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

with atheris.instrument_imports():
    import kitcases

VERIFIER = kitcases.load_verifier()
atheris.instrument_all()


class _FuzzedChoices:
    """The ``randrange`` that ``kitcases.mutate`` draws from, answered by the fuzzer's bytes."""

    def __init__(self, provider: atheris.FuzzedDataProvider) -> None:
        self._provider = provider

    def randrange(self, start: int, stop: int | None = None) -> int:
        low, high = (0, start) if stop is None else (start, stop)
        if high - low <= 1:
            return low
        return int(self._provider.ConsumeIntInRange(low, high - 1))


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)
    base = Path(tempfile.mkdtemp(prefix="fuzz-verify-"))
    try:
        kit = kitcases.fresh_kit(base)
        if provider.ConsumeBool():
            applied = ["raw manifest"]
            (kit / kitcases.MANIFEST).write_bytes(provider.ConsumeBytes(provider.remaining_bytes()))
        else:
            applied = kitcases.mutate(_FuzzedChoices(provider), kit)
        before = kitcases.fingerprint(base)
        outcome = kitcases.run_in_process(VERIFIER, kit)
        found = kitcases.violations(kit, outcome)
        if kitcases.fingerprint(base) != before:
            found.setdefault("c", []).append("the kit folder changed")
        if found:
            raise AssertionError(f"D1 broken after {applied}: {found}\n{outcome.stdout[:500]}")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
