#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Oversight Proof LLC
# Licensed under the Apache License, Version 2.0. See the LICENSE file included in
# this kit, or http://www.apache.org/licenses/LICENSE-2.0
"""Standalone, offline verifier for an OversightProof evidence kit. This is the TRUST ANCHOR.

This script depends on NOTHING but the Python standard library (Python 3.11 or newer). It does not
load the oversight_proof package, makes no network calls, and writes no files. Hand the whole kit
folder to a third party; they can run it with a stock Python interpreter and check, from the file
bytes alone, that the packet's files match its manifest.

What it checks:
  1. It recomputes a SHA-256 hash chain over every file in the packet (sorted by path, excluding
     only the integrity manifest at the packet root), exactly as the tool did when it built it.
  2. It confirms the recomputed root matches the manifest's stored root and the expected root
     recorded in provenance.json, and, with --expect-root, the root you supply.
  3. It detects a single changed byte (one file's hash will differ), a deleted file, an added file,
     and an empty packet, and names the offending path.

WHAT A PASS MEANS DEPENDS ON WHERE THE ROOT CAME FROM. The manifest and provenance.json travel in
the same kit as the files they describe, so someone who edits a file can edit them too. Without
--expect-root, PASS means the kit is INTERNALLY CONSISTENT: every file matches the manifest and the
root recorded in this kit. With --expect-root and a root you received separately (by email, on a
ticket, in a contract), PASS means the packet matches that root.

What it does NOT do: it does not judge whether the underlying human review was adequate, it does not
re-run the tool, and it is not a legal or regulatory compliance determination.

Usage:
    python verify.py                         # verify the kit this script sits in
    python verify.py <kit-dir>               # verify a kit at the given path
    python verify.py <kit-dir> --expect-root <64-hex root you received separately>
    python verify.py <kit-dir> --json
Exit code: 0 on PASS, 1 on FAIL, 2 when the command line itself is wrong (nothing was checked).
Every path it prints is relative to the kit folder.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

GENESIS = hashlib.sha256(b"OEA-GENESIS-v1").hexdigest()
_MANIFEST_NAME = "integrity_manifest.json"

# The ONLY file the kit writer is able to redact. provenance.json sits outside packet/ by
# construction, so it is not covered by the manifest or the hash chain; without this allowlist an
# edited provenance.json could name any manifest file as "redacted" and have it bound by its
# RECORDED hash instead of re-derived from bytes, which lets deleted evidence rebuild the expected
# root. The writer only ever emits [] or exactly [_ENVELOPE_NAME] (a non-evidence input file).
# Keep this in step with _ENVELOPE_NAME in src/oversight_proof/verify/kit.py. The duplication is
# deliberate: this verifier is standalone by design and must not import the engine.
_ENVELOPE_NAME = "snapshot_envelope.json"
_ALLOWED_REDACTED = frozenset({_ENVELOPE_NAME})

# --- canonical hashing, ported faithfully from the tool's core (stdlib only) -----------------
_ISO_Z = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?"
    r"(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$"
)


def _normalize_timestamp(value: str) -> str:
    # In lockstep with core/serialize.py normalize_timestamp, which is the reference: an explicit
    # non-UTC offset is shifted to UTC and emitted as Z, Z / +00:00 / +0000 / offset-less emit Z,
    # and canonicalization is TOTAL -- a value that does not match the shape, OR matches it but is
    # not a valid instant (month 13, day 99, hour 25, or the leap second 23:59:60, all of which
    # `datetime` rejects), is returned UNCHANGED so it hashes as ordinary data rather than aborting
    # the hash path. That is the engine's deliberate decision, not an oversight, and a verifier that
    # raised instead would crash on a packet the engine considers valid.
    #
    # Lockstep is enforced by tests/kit/test_kit_engine_lockstep.py, which runs this function and
    # the engine's over one shared vector table and requires byte-identical results. A comment
    # cannot enforce it; that test can. This file still imports nothing from the engine.
    m = _ISO_Z.match(value)
    if not m:
        return value
    year, mon, day, hh, mm, ss, frac, off = m.groups()
    ss = ss or "00"
    if frac:
        frac = frac.rstrip("0")
    try:
        instant = datetime(int(year), int(mon), int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return value
    if off not in (None, "Z", "+0000", "+00:00"):
        digits = off[1:].replace(":", "")
        delta = timedelta(minutes=int(digits[:2]) * 60 + int(digits[2:4]))
        instant = instant - delta if off[0] == "+" else instant + delta
    base = (
        f"{instant.year:04d}-{instant.month:02d}-{instant.day:02d}"
        f"T{instant.hour:02d}:{instant.minute:02d}:{instant.second:02d}"
    )
    if frac:
        base += f".{frac}"
    return base + "Z"


def _canonicalize(value: Any) -> Any:
    if isinstance(value, str):
        return _normalize_timestamp(value)
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return {str(k): _canonicalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _content_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _link_hash(index: int, record_id: str, content: str, prev_hash: str) -> str:
    return _content_hash(
        {"content_hash": content, "index": index, "prev_hash": prev_hash, "record_id": record_id}
    )


def _chain_root(records: list[dict[str, Any]]) -> str:
    """Records are [{record_id, payload}] in committed (path-sorted) order."""
    prev = GENESIS
    for i, rec in enumerate(records):
        c = _content_hash(rec["payload"])
        prev = _link_hash(i, str(rec["record_id"]), c, prev)
    return prev  # the head of the chain (GENESIS for an empty chain)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# --- verification ----------------------------------------------------------------------------


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty relative path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"{label} must stay inside the kit")
    return value


def _safe_packet_file(packet_dir: Path, rel: str) -> Path:
    safe = _safe_relative(rel, "manifest file path")
    target = (packet_dir / safe).resolve()
    root = packet_dir.resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"manifest file path escapes packet/: {rel}")
    return target


def _safe_manifest_name(value: object) -> str:
    name = value if isinstance(value, str) and value else _MANIFEST_NAME
    if Path(name).name != name or name in (".", ".."):
        raise ValueError("manifest_file must be a file name, not a path")
    return name


def _safe_redacted(values: object) -> set[str]:
    out: set[str] = set()
    if not isinstance(values, list):
        return out
    for value in values:
        out.add(_safe_relative(value, "redacted file path"))
    return out


_HEX_ROOT = re.compile(r"[0-9a-f]{64}")


def _rel(kit_dir: Path, path: Path) -> str:
    """``path`` as the user sees it: relative to the kit folder they passed, never absolute."""
    try:
        return path.resolve().relative_to(kit_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def verify_kit(kit_dir: Path, expect_root: str | None = None) -> dict[str, Any]:
    """Check the kit at ``kit_dir``; with ``expect_root``, also against a root supplied separately.

    ``expect_root`` is a lowercase 64-character hex SHA-256, already validated by the caller.
    """
    problems: list[str] = []
    root_source = "supplied" if expect_root is not None else "kit"

    prov_path = kit_dir / "provenance.json"
    if not prov_path.is_file():
        return {
            "ok": False,
            "root_source": root_source,
            "problems": ["provenance.json not found in the kit folder"],
        }
    prov = json.loads(prov_path.read_text(encoding="utf-8"))

    try:
        packet_rel = _safe_relative(prov.get("packet_dir", "packet"), "packet_dir")
        packet_dir = (kit_dir / packet_rel).resolve()
        kit_root = kit_dir.resolve()
        if packet_dir != kit_root and kit_root not in packet_dir.parents:
            raise ValueError("packet_dir escapes the kit")
        manifest_name = _safe_manifest_name(prov.get("manifest_file", _MANIFEST_NAME))
        redacted = _safe_redacted(prov.get("redacted_files", []))
    except ValueError as exc:
        return {"ok": False, "root_source": root_source, "problems": [str(exc)]}

    # Only the writer's one redactable input may shield a file from byte re-derivation. Anything
    # else is dropped from the set, so a manifest file named here but missing from the packet falls
    # through to the existing "deleted file" report below. The unexpected entry is itself reported:
    # the writer cannot produce one, so its presence means provenance.json was edited.
    unexpected_redactions = sorted(redacted - _ALLOWED_REDACTED)
    redacted &= _ALLOWED_REDACTED

    expected_root = prov.get("expected_manifest_root_hash")

    manifest_path = packet_dir / manifest_name
    shown_manifest = _rel(kit_dir, manifest_path)
    if manifest_path.is_symlink():
        return {
            "ok": False,
            "root_source": root_source,
            "problems": [f"integrity manifest is a symlink: {shown_manifest}"],
        }
    if not manifest_path.is_file():
        return {
            "ok": False,
            "root_source": root_source,
            "problems": [f"integrity manifest not found: {shown_manifest}"],
        }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    stored = manifest.get("files", [])
    stored_root = manifest.get("root_hash")
    stored_hash = {}
    try:
        for f in stored:
            path = _safe_relative(f["path"], "manifest file path")
            stored_hash[path] = f["sha256"]
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "ok": False,
            "root_source": root_source,
            "problems": [f"invalid manifest file entry: {exc}"],
        }

    for name in unexpected_redactions:
        problems.append(
            f"provenance.json lists a file as redacted that the kit writer never redacts: {name}"
        )

    # ONLY THE MANIFEST AT THE PACKET ROOT IS EXEMPT, by its exact relative path. A file of the
    # same name anywhere else is an ordinary file: it must be listed in the manifest, or the check
    # fails. Exempting the name at any depth let a file be added under that name and pass unseen.
    present = []
    for p in packet_dir.rglob("*"):
        rel = p.relative_to(packet_dir).as_posix()
        if p.is_symlink():
            problems.append(f"symlink not allowed in packet: {rel}")
            continue
        if p.is_file() and rel != manifest_name:
            present.append(rel)
    present = sorted(present)
    for path in present:
        if path not in stored_hash:
            problems.append(f"added file not present in the manifest: {path}")

    # Rebuild the chain over the manifest's files in canonical (path-sorted) order, recomputing
    # each present file's hash from its bytes. A redacted file is bound by its recorded hash.
    records: list[dict[str, Any]] = []
    for path in sorted(stored_hash):
        want = stored_hash[path]
        try:
            fpath = _safe_packet_file(packet_dir, path)
        except ValueError as exc:
            problems.append(str(exc))
            continue
        if fpath.is_file():
            got = _sha256_file(fpath)
            if got != want:
                problems.append(f"content changed: {path}")
            records.append({"record_id": path, "payload": {"sha256": got}})
        elif path in redacted:
            records.append({"record_id": path, "payload": {"sha256": want}})
        else:
            problems.append(f"deleted file (in the manifest, missing from the packet): {path}")

    # ZERO FILES IS A FAIL. The chain over no records is the genesis value, and a manifest and a
    # provenance.json that both record it would otherwise agree with it: a kit holding nothing
    # passed, reporting "files checked: 0". An empty packet is not evidence of anything.
    if not records:
        problems.append(
            "the packet holds no files to check: an empty packet carries no evidence, so it cannot "
            "pass"
        )

    recomputed_root = _chain_root(records)
    root_matches_manifest = recomputed_root == stored_root
    if not root_matches_manifest:
        problems.append(
            f"root does not match the manifest (recomputed {recomputed_root}, "
            f"manifest {stored_root})"
        )
    # The expected root is MANDATORY. It was previously optional, so removing the key from the
    # unsigned provenance.json skipped this comparison entirely -- and an attacker editing that file
    # controls the redaction list and the expected root at once. The writer emits it on every kit.
    if expected_root is None:
        problems.append(
            "provenance.json has no expected_manifest_root_hash: the recomputed root cannot be "
            "checked against the value recorded when the kit was emitted"
        )
    elif recomputed_root != expected_root:
        problems.append(
            f"root does not match provenance.json (recomputed {recomputed_root}, "
            f"expected {expected_root})"
        )
    # THE ONE ROOT THAT DID NOT TRAVEL WITH THE KIT. The manifest and provenance.json can both be
    # edited by whoever edits a file; a root the recipient received separately cannot.
    if expect_root is not None and recomputed_root != expect_root:
        problems.append(
            f"root does not match the one you supplied (recomputed {recomputed_root}, "
            f"supplied {expect_root})"
        )

    ok = not problems
    result: dict[str, Any] = {
        "ok": ok,
        "packet_dir": packet_rel,
        "record_count": len(records),
        "recomputed_root": recomputed_root,
        "manifest_root": stored_root,
        "expected_root": expected_root,
        "root_source": root_source,
        "redacted_files": sorted(redacted),
        "problems": problems,
    }
    if expect_root is not None:
        result["supplied_root"] = expect_root
    return result


_USAGE = "usage: python verify.py [<kit-dir>] [--expect-root <64-hex root>] [--json]"


def _parse_args(argv: list[str]) -> tuple[str | None, bool, str | None]:
    """``(kit_dir or None, as_json, expect_root or None)``; raises ValueError on a bad command line.

    Parsed by hand rather than with argparse, so the imports stay the short list the published
    README names.
    """
    kit: str | None = None
    as_json = False
    expect: str | None = None
    args = list(argv[1:])
    while args:
        arg = args.pop(0)
        if arg == "--json":
            as_json = True
        elif arg == "--expect-root" or arg.startswith("--expect-root="):
            if arg == "--expect-root":
                if not args:
                    raise ValueError("--expect-root needs the root hash after it")
                value = args.pop(0)
            else:
                value = arg.split("=", 1)[1]
            value = value.strip().lower()
            if not _HEX_ROOT.fullmatch(value):
                raise ValueError(
                    "--expect-root must be the 64-character hexadecimal root hash you received, "
                    f"got {value!r}"
                )
            expect = value
        elif arg.startswith("-"):
            raise ValueError(f"unknown option {arg!r}")
        elif kit is None:
            kit = arg
        else:
            raise ValueError(f"more than one kit folder given: {kit!r} and {arg!r}")
    return kit, as_json, expect


#: Exit codes. 2 is a command line this script could not read; nothing was checked.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

_CONFIRM_HINT = (
    "To confirm the packet is the one that was sent, compare this root with one you received "
    "separately, or run again with --expect-root."
)


def _pass_headline(result: dict[str, Any]) -> list[str]:
    """The PASS lines, worded by where the root came from. Never more than was checked."""
    root = result["recomputed_root"]
    supplied = result["root_source"] == "supplied"
    redacted_files = result.get("redacted_files") or []
    if redacted_files:
        # Not "every file": a redacted file's integrity is asserted from the manifest's recorded
        # hash, not derived from bytes we can see. Say so in the headline, not a footnote.
        verified = result["record_count"] - len(redacted_files)
        counts = (
            f"{verified} files verified, {len(redacted_files)} bound by recorded hash "
            "(not re-derived)"
        )
        if supplied:
            return [
                f"PASS with redaction: {counts}, and the root matches the one you supplied "
                f"({root})."
            ]
        return [
            f"PASS with redaction (internally consistent): {counts}, and the root matches the one "
            f"recorded in this kit ({root}). {_CONFIRM_HINT}"
        ]
    if supplied:
        return [
            "PASS: every file matches the manifest, and the root matches the one you supplied "
            f"({root})."
        ]
    return [
        "PASS (internally consistent): every file matches the manifest and the root recorded in "
        f"this kit ({root}). {_CONFIRM_HINT}"
    ]


def main(argv: list[str]) -> int:
    try:
        kit_arg, as_json, expect_root = _parse_args(argv)
    except ValueError as exc:
        print(f"verify.py: {exc}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        return EXIT_USAGE
    kit_dir = Path(kit_arg) if kit_arg is not None else Path(__file__).resolve().parent
    result = verify_kit(kit_dir, expect_root)

    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_PASS if result["ok"] else EXIT_FAIL

    if result["ok"]:
        redacted_files = result.get("redacted_files") or []
        for line in _pass_headline(result):
            print(line)
        print(f"  files checked: {result['record_count']}")
        print(f"  root: {result['recomputed_root']}")
        if redacted_files:
            print(f"  redacted (bound by recorded hash, not re-derived): {redacted_files}")
        print("This checks the packet's files against that root. It is not a compliance finding.")
        return EXIT_PASS

    print("FAIL: the evidence packet did not verify.")
    for problem in result["problems"]:
        print(f"  - {problem}")
    return EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
