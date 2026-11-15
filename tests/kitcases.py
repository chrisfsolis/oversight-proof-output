# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Oversight Proof LLC
# Licensed under the Apache License, Version 2.0. See the LICENSE file in this repository, or
# http://www.apache.org/licenses/LICENSE-2.0
"""Hostile verification kits, built on demand, and the rules ``verify.py`` must hold on any of them.

Standard library only, like the verifier. Three things live here, and everything that tests the
verifier imports them rather than keeping its own copy:

* WHERE THINGS ARE. ``verify_py()`` is the verifier under test, named by the ``VERIFY_PY``
  environment variable and otherwise ``verify.py`` at the top of the repository holding this
  folder. ``reference_kit()`` is ``examples/kit/reference_packet``, the published worked example,
  found by walking up from this file.
* THE NAMED CASES. ``CASES`` maps a name to a function that turns a fresh copy of the reference
  kit into one hostile kit -- one trick each. Where the trick would otherwise fail on a root
  mismatch, the case re-seals both roots so the trick is the only defect left to find.
* THE MUTATIONS AND THE ORACLE. ``mutate()`` applies random edits drawn from any source with a
  ``randrange`` method (a seeded ``random.Random``, or a fuzzer's byte stream); ``bytes_match()``
  says, independently of the verifier, whether a kit's files really match its manifest and roots.
* THE WATCHED RUN. ``run_in_process()`` calls the verifier's ``main`` under an audit hook that
  records every file opened, folder listed, file-system change and socket event; ``violations()``
  turns one run into the D1 items it breaks.

Nothing here touches the network, and every kit is built under a folder the caller owns.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol

GENESIS = hashlib.sha256(b"OEA-GENESIS-v1").hexdigest()
MANIFEST = Path("packet") / "integrity_manifest.json"
PROVENANCE = Path("provenance.json")
OUTSIDE_NAME = "outside.txt"
OUTSIDE_BYTES = b"A FILE OUTSIDE THE KIT. verify.py must never open this.\n"

EXIT_PASS, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
FAIL_HEADLINE = "FAIL: the evidence packet did not verify."


# --- where things are -----------------------------------------------------------------------------


def repository_root() -> Path:
    """The folder holding ``examples/kit/reference_packet``, found by walking up from this file."""
    for folder in Path(__file__).resolve().parents:
        if (folder / "examples" / "kit" / "reference_packet" / "provenance.json").is_file():
            return folder
    raise FileNotFoundError("no examples/kit/reference_packet above " + str(Path(__file__)))


def verify_py() -> Path:
    """The verifier under test: ``$VERIFY_PY``, else ``verify.py`` at the repository's top."""
    named = os.environ.get("VERIFY_PY")
    path = Path(named) if named else repository_root() / "verify.py"
    if not path.is_file():
        raise FileNotFoundError(f"no verifier at {path}; set VERIFY_PY to the verify.py to test")
    return path.resolve()


def reference_kit() -> Path:
    return repository_root() / "examples" / "kit" / "reference_packet"


# --- building and sealing a kit -------------------------------------------------------------------


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def chain_root(entries: list[tuple[str, str]]) -> str:
    """The manifest root over ``(path, sha256)`` pairs in the order given."""
    prev = GENESIS
    for index, (path, sha) in enumerate(entries):
        content = _hash({"sha256": sha})
        prev = _hash(
            {"content_hash": content, "index": index, "prev_hash": prev, "record_id": path}
        )
    return prev


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fresh_kit(base: Path) -> Path:
    """A copy of the reference kit at ``base/kit``, and a file beside it that must stay unopened."""
    kit = base / "kit"
    shutil.copytree(reference_kit(), kit, ignore=shutil.ignore_patterns("__pycache__"))
    (base / OUTSIDE_NAME).write_bytes(OUTSIDE_BYTES)
    return kit


def outside_file(kit: Path) -> Path:
    return kit.parent / OUTSIDE_NAME


def load_manifest(kit: Path) -> dict[str, Any]:
    value: dict[str, Any] = json.loads((kit / MANIFEST).read_bytes())
    return value


def seal(kit: Path, manifest: dict[str, Any], entries: list[tuple[str, str]] | None = None) -> None:
    """Write ``manifest`` with both roots set to the chain over ``entries`` -- by default the
    manifest's own files, one per path, in sorted order, the way the verifier walks them."""
    if entries is None:
        by_path = {f["path"]: f["sha256"] for f in manifest["files"]}
        entries = sorted(by_path.items())
    root = chain_root(entries)
    manifest["root_hash"] = root
    (kit / MANIFEST).write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
    provenance = json.loads((kit / PROVENANCE).read_bytes())
    provenance["expected_manifest_root_hash"] = root
    (kit / PROVENANCE).write_bytes(json.dumps(provenance).encode("utf-8"))


def can_symlink(base: Path) -> bool:
    """Whether this machine lets an ordinary user make a symlink (Windows needs developer mode)."""
    probe = base / "symlink-probe"
    try:
        os.symlink(base, probe, target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


# --- the named cases ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One hostile kit. ``build`` edits a fresh copy; ``needs`` is "symlink", "junction" or "".
    ``reason`` is a phrase the verifier's one-line reason must contain; "|" separates phrases
    of which any one will do (Windows and POSIX read some paths differently). Every case must fail
    closed; DECISIONS.md ("Verifier hardening") records which ones the verifier published before
    2026-11-14 did not."""

    item: str  # the D1 item it tests: a, b, c, d or e
    build: Callable[[Path], None]
    reason: str
    needs: str = ""
    console: str = "utf-8"  # the encoding the verifier's output is written in


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _replace(path: Path, old: bytes, new: bytes) -> None:
    data = path.read_bytes()
    assert old in data, f"{old!r} not in {path}"
    path.write_bytes(data.replace(old, new, 1))


def _add_entry(kit: Path, path: str, sha: str) -> None:
    manifest = load_manifest(kit)
    manifest["files"].append({"path": path, "sha256": sha})
    seal(kit, manifest)


def _one_changed_byte(kit: Path) -> None:
    target = kit / "packet" / "audit-consistency" / "run_manifest.json"
    data = bytearray(target.read_bytes())
    data[10] ^= 0x01
    target.write_bytes(bytes(data))


def _forged_roots(kit: Path) -> None:
    # A changed file AND both roots rebuilt over its RECORDED hash: the roots agree with each
    # other, and only the bytes give the change away.
    _one_changed_byte(kit)
    seal(kit, load_manifest(kit))


def _swapped_hashes(kit: Path) -> None:
    manifest = load_manifest(kit)
    first, second = manifest["files"][0], manifest["files"][1]
    first["sha256"], second["sha256"] = second["sha256"], first["sha256"]
    seal(kit, manifest)


def _prov_bad_json(kit: Path) -> None:
    _write(kit / PROVENANCE, b"{not json")


def _manifest_bad_json(kit: Path) -> None:
    _write(kit / MANIFEST, b'{"files": [')


def _manifest_invalid_utf8(kit: Path) -> None:
    _write(kit / MANIFEST, b'{"files": [], "root_hash": "\xff\xfe"}')


def _manifest_bom(kit: Path) -> None:
    _write(kit / MANIFEST, b"\xef\xbb\xbf" + (kit / MANIFEST).read_bytes())


def _manifest_nan(kit: Path) -> None:
    _replace(kit / MANIFEST, b'"record_count": 75', b'"record_count": NaN')


def _prov_infinity(kit: Path) -> None:
    _replace(kit / PROVENANCE, b'"as_of"', b'"x": Infinity, "as_of"')


def _manifest_duplicate_key(kit: Path) -> None:
    # Two "files" keys: Python keeps the LAST, another reader might keep the first.
    _replace(kit / MANIFEST, b'"files": [', b'"files": [], "files": [')


def _prov_is_list(kit: Path) -> None:
    _write(kit / PROVENANCE, b"[]")


def _manifest_is_list(kit: Path) -> None:
    _write(kit / MANIFEST, b"[]")


def _files_is_object(kit: Path) -> None:
    manifest = load_manifest(kit)
    manifest["files"] = {"a": 1}
    _write(kit / MANIFEST, json.dumps(manifest).encode())


def _entry_path_not_a_string(kit: Path) -> None:
    manifest = load_manifest(kit)
    manifest["files"][0]["path"] = 7
    _write(kit / MANIFEST, json.dumps(manifest).encode())


def _entry_without_hash(kit: Path) -> None:
    manifest = load_manifest(kit)
    del manifest["files"][0]["sha256"]
    _write(kit / MANIFEST, json.dumps(manifest).encode())


def _no_expected_root(kit: Path) -> None:
    provenance = json.loads((kit / PROVENANCE).read_bytes())
    del provenance["expected_manifest_root_hash"]
    _write(kit / PROVENANCE, json.dumps(provenance).encode())


def _duplicate_path(kit: Path) -> None:
    manifest = load_manifest(kit)
    manifest["files"].append(dict(manifest["files"][0]))
    seal(kit, manifest)


def _duplicate_path_other_hash(kit: Path) -> None:
    manifest = load_manifest(kit)
    manifest["files"].insert(0, {"path": manifest["files"][0]["path"], "sha256": "0" * 64})
    seal(kit, manifest)


def _case_collision(kit: Path) -> None:
    manifest = load_manifest(kit)
    first = manifest["files"][0]
    manifest["files"].append({"path": first["path"].upper(), "sha256": first["sha256"]})
    seal(kit, manifest)


def _normalization_collision(kit: Path) -> None:
    packet = kit / "packet"
    composed = "caf\u00e9.json"
    decomposed = unicodedata.normalize("NFD", composed)
    (packet / composed).write_bytes(b"{}")
    try:
        (packet / decomposed).write_bytes(b"[]")
    except OSError:
        pass  # a file system that normalizes names already made them one file
    manifest = load_manifest(kit)
    for name in dict.fromkeys((composed, decomposed)):
        if (packet / name).is_file():
            manifest["files"].append({"path": name, "sha256": sha256_file(packet / name)})
    seal(kit, manifest)


def _empty_packet(kit: Path) -> None:
    for child in sorted((kit / "packet").iterdir()):
        if child.name != MANIFEST.name:
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    seal(kit, {"files": []}, [])


def _dotdot_entry(kit: Path) -> None:
    _add_entry(kit, "../../" + OUTSIDE_NAME, sha256_file(outside_file(kit)))


def _absolute_entry(kit: Path) -> None:
    _add_entry(kit, str(outside_file(kit)), sha256_file(outside_file(kit)))


def _drive_relative_entry(kit: Path) -> None:
    _add_entry(kit, "C:" + OUTSIDE_NAME, sha256_file(outside_file(kit)))


def _unc_entry(kit: Path) -> None:
    _add_entry(kit, "//localhost/c$/" + OUTSIDE_NAME, "0" * 64)


def _backslash_dotdot_entry(kit: Path) -> None:
    _add_entry(kit, "..\\..\\" + OUTSIDE_NAME, sha256_file(outside_file(kit)))


def _packet_dir_escapes(kit: Path) -> None:
    provenance = json.loads((kit / PROVENANCE).read_bytes())
    provenance["packet_dir"] = ".."
    _write(kit / PROVENANCE, json.dumps(provenance).encode())


def _symlinked_file_out(kit: Path) -> None:
    os.symlink(outside_file(kit), kit / "packet" / "leak.txt")
    _add_entry(kit, "leak.txt", sha256_file(outside_file(kit)))


def _symlinked_folder_out(kit: Path) -> None:
    folder = kit.parent / "outside-folder"
    folder.mkdir()
    (folder / OUTSIDE_NAME).write_bytes(OUTSIDE_BYTES)
    os.symlink(folder, kit / "packet" / "linked", target_is_directory=True)
    _add_entry(kit, "linked/" + OUTSIDE_NAME, sha256_file(folder / OUTSIDE_NAME))


def _junction_out(kit: Path) -> None:
    if sys.platform != "win32":  # the case needs "junction"; junctions exist only on Windows
        raise OSError("junctions exist only on Windows")
    import _winapi

    folder = kit.parent / "outside-folder"
    folder.mkdir()
    (folder / OUTSIDE_NAME).write_bytes(OUTSIDE_BYTES)
    _winapi.CreateJunction(str(folder), str(kit / "packet" / "junction"))
    _add_entry(kit, "junction/" + OUTSIDE_NAME, sha256_file(folder / OUTSIDE_NAME))


def _symlinked_provenance_out(kit: Path) -> None:
    moved = kit.parent / "provenance-outside.json"
    shutil.move(str(kit / PROVENANCE), str(moved))
    os.symlink(moved, kit / PROVENANCE)


def _symlinked_packet_out(kit: Path) -> None:
    moved = kit.parent / "packet-outside"
    shutil.move(str(kit / "packet"), str(moved))
    os.symlink(moved, kit / "packet", target_is_directory=True)


def _symlinked_manifest_out(kit: Path) -> None:
    moved = kit.parent / "manifest-outside.json"
    shutil.move(str(kit / MANIFEST), str(moved))
    os.symlink(moved, kit / MANIFEST)


def _newline_in_a_name(kit: Path) -> None:
    _add_entry(kit, "x\nPASS: every file matches the manifest.", "0" * 64)


def _bidi_and_emoji_in_a_name(kit: Path) -> None:
    _add_entry(kit, "\U0001f600\u202ejson.exe", "0" * 64)


def _deep_manifest(kit: Path) -> None:
    _write(kit / MANIFEST, b"[" * 100_000 + b"]" * 100_000)


def _deep_provenance(kit: Path) -> None:
    _write(kit / PROVENANCE, b'{"a":' * 100_000 + b"1" + b"}" * 100_000)


def _fifty_megabyte_manifest(kit: Path) -> None:
    manifest = load_manifest(kit)
    manifest["padding"] = "x" * (50 * 1024 * 1024)
    _write(kit / MANIFEST, json.dumps(manifest).encode())


def _too_many_entries(kit: Path) -> None:
    # Over the entry limit while far under the size limit: 12,000 short entries, about 1 MB.
    manifest = load_manifest(kit)
    manifest["files"] += [{"path": f"n/{i}", "sha256": "0"} for i in range(12_000)]
    _write(kit / MANIFEST, json.dumps(manifest).encode())


def _deep_folders(kit: Path) -> None:
    folder = kit / "packet"
    for _ in range(40):
        folder = folder / "d"
    folder.mkdir(parents=True)


def _huge_integer(kit: Path) -> None:
    _replace(kit / MANIFEST, b'"record_count": 75', b'"record_count": ' + b"9" * 5000)


def _unreadable_folder_name(kit: Path) -> None:
    # A file the walk finds but the manifest does not list, named with a character no console
    # encoding shares: the report must name it without crashing.
    (kit / "packet" / "\u2603\u202e.txt").write_bytes(b"added\n")


CASES: dict[str, Case] = {
    # D1a: no PASS unless the bytes match the manifest and both roots.
    "one_changed_byte": Case("a", _one_changed_byte, "content changed"),
    "forged_roots": Case("a", _forged_roots, "content changed"),
    "swapped_hashes": Case("a", _swapped_hashes, "content changed"),
    "no_expected_root": Case("a", _no_expected_root, "expected_manifest_root_hash"),
    # D1b: nothing outside the kit is read.
    "dotdot_entry": Case("b", _dotdot_entry, "inside the kit"),
    "absolute_entry": Case("b", _absolute_entry, "inside the kit"),
    "drive_relative_entry": Case("b", _drive_relative_entry, "C:outside.txt"),
    "unc_entry": Case("b", _unc_entry, "inside the kit"),
    "backslash_dotdot_entry": Case("b", _backslash_dotdot_entry, "inside the kit|outside.txt"),
    "packet_dir_escapes": Case("b", _packet_dir_escapes, "packet_dir"),
    "symlinked_file_out": Case("b", _symlinked_file_out, "symlink", "symlink"),
    "symlinked_folder_out": Case("b", _symlinked_folder_out, "symlink", "symlink"),
    "junction_out": Case("b", _junction_out, "junction not allowed", "junction"),
    "symlinked_provenance_out": Case("b", _symlinked_provenance_out, "provenance.json", "symlink"),
    "symlinked_packet_out": Case("b", _symlinked_packet_out, "packet_dir", "symlink"),
    "symlinked_manifest_out": Case("b", _symlinked_manifest_out, "symlink", "symlink"),
    # D1d: bounded on a hostile kit.
    "deep_manifest": Case("d", _deep_manifest, "deeper than"),
    "deep_provenance": Case("d", _deep_provenance, "deeper than"),
    "fifty_megabyte_manifest": Case("d", _fifty_megabyte_manifest, "larger than"),
    "too_many_entries": Case("d", _too_many_entries, "at most"),
    "deep_folders": Case("d", _deep_folders, "deeper than"),
    # D1e: one of the three exit codes and a one-line reason, never a traceback.
    "provenance_bad_json": Case("e", _prov_bad_json, "provenance.json"),
    "manifest_bad_json": Case("e", _manifest_bad_json, "not valid JSON"),
    "manifest_invalid_utf8": Case("e", _manifest_invalid_utf8, "UTF-8"),
    "manifest_byte_order_mark": Case("e", _manifest_bom, "BOM"),
    "manifest_nan": Case("e", _manifest_nan, "NaN"),
    "provenance_infinity": Case("e", _prov_infinity, "Infinity"),
    "manifest_duplicate_key": Case("e", _manifest_duplicate_key, "repeats the key"),
    "provenance_is_a_list": Case("e", _prov_is_list, "JSON object"),
    "manifest_is_a_list": Case("e", _manifest_is_list, "JSON object"),
    "files_is_an_object": Case("e", _files_is_object, "invalid manifest"),
    "entry_path_not_a_string": Case("e", _entry_path_not_a_string, "non-empty relative path"),
    "entry_without_hash": Case("e", _entry_without_hash, "sha256"),
    "huge_integer": Case("e", _huge_integer, "integer"),
    "duplicate_path": Case("e", _duplicate_path, "twice"),
    "duplicate_path_other_hash": Case("e", _duplicate_path_other_hash, "twice"),
    "case_collision": Case("e", _case_collision, "letter case"),
    "normalization_collision": Case("e", _normalization_collision, "Unicode form"),
    "empty_packet": Case("e", _empty_packet, "no files to check"),
    "newline_in_a_name": Case("e", _newline_in_a_name, "\\u000a"),
    "bidi_and_emoji_in_a_name": Case("e", _bidi_and_emoji_in_a_name, "\\u202e", console="ascii"),
    "unreadable_name_in_packet": Case("e", _unreadable_folder_name, "added file", console="ascii"),
}


def build(name: str, base: Path) -> Path:
    """The kit for case ``name``, built under ``base`` (which must be empty)."""
    kit = fresh_kit(base)
    CASES[name].build(kit)
    return kit


# --- running the verifier -------------------------------------------------------------------------


@dataclass(frozen=True)
class Run:
    code: int
    stdout: str
    stderr: str


def run(kit: Path, *args: str, verifier: Path | None = None, console: str = "utf-8") -> Run:
    """``python verify.py <kit> <args>`` in a child process, as a recipient would run it, its
    output written in the ``console`` encoding."""
    env = dict(os.environ, PYTHONIOENCODING=console, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        # Not -I: isolated mode ignores PYTHONIOENCODING, which is how ``console`` is chosen.
        [sys.executable, "-s", str(verifier or verify_py()), str(kit), *args],
        capture_output=True,
        env=env,
        timeout=600,
        check=False,
    )
    return Run(
        proc.returncode,
        proc.stdout.decode("utf-8", "backslashreplace"),
        proc.stderr.decode("utf-8", "backslashreplace"),
    )


def fail_closed_problems(result: Run, reason: str) -> list[str]:
    """What keeps ``result`` from being a clean FAIL naming ``reason``, one line per reason."""
    problems: list[str] = []
    if result.code != EXIT_FAIL:
        problems.append(f"exit code {result.code}, not {EXIT_FAIL}")
    if "Traceback" in result.stderr:
        problems.append("a traceback: " + result.stderr.strip().splitlines()[-1])
    lines = result.stdout.splitlines()
    if not lines or lines[0] != FAIL_HEADLINE:
        problems.append(f"the first line is not the FAIL headline: {lines[:1]}")
    elif any(not line.startswith("  - ") for line in lines[1:]) or len(lines) < 2:
        problems.append("a reason is not exactly one line: " + repr(result.stdout[:300]))
    if not any(phrase in result.stdout for phrase in reason.split("|")):
        problems.append(f"no reason names {reason!r}: " + repr(result.stdout[:300]))
    return problems


# --- the oracle: do the bytes match? --------------------------------------------------------------


def is_link(path: Path) -> bool:
    """A symlink, or a Windows junction (which ``is_symlink`` does not report)."""
    if path.is_symlink():
        return True
    try:
        return getattr(path.lstat(), "st_reparse_tag", 0) == 0xA0000003
    except OSError:
        return False


def tree(root: Path) -> dict[str, str]:
    """Every entry under ``root``: a file's SHA-256, or what kind of thing it is otherwise."""
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if is_link(path):
                out[rel] = "link -> " + os.readlink(path)
            elif path.is_file():
                out[rel] = sha256_file(path)
            else:
                out[rel] = "folder"
    return out


def fingerprint(root: Path) -> dict[str, tuple[int, int, int]]:
    """Every entry under ``root`` as ``(mode, size, modification time)``, read with ``lstat``:
    cheap enough to take before and after every fuzz case, and changed by any write."""
    out: dict[str, tuple[int, int, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = path.lstat()
            out[path.relative_to(root).as_posix()] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return out


def bytes_match(kit: Path) -> bool:
    """Whether the kit's packet files, as bytes, match its manifest and both of its roots.

    Read as leniently as a careless reader would (the last of two duplicate keys wins, NaN is a
    number, a path listed twice counts once): a verifier that says PASS where this says False has
    passed a kit whose bytes do not match, which is the one thing it must never do (D1a). A PASS
    where this says True can still be wrong for another reason; ``ambiguous()`` covers those.
    """
    try:
        provenance = json.loads((kit / PROVENANCE).read_bytes())
        packet_dir = provenance.get("packet_dir", "packet")
        # The verifier reads packet_dir the way pathlib does ("./packet" and "packet/." are packet).
        if not isinstance(packet_dir, str) or Path(packet_dir).parts != ("packet",):
            return False
        manifest = json.loads((kit / "packet" / manifest_name(provenance)).read_bytes())
        listed = {f["path"]: f["sha256"] for f in manifest["files"]}
        redacted = set(provenance.get("redacted_files") or []) & {"snapshot_envelope.json"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return False
    packet = kit / "packet"
    on_disk = {
        rel: digest
        for rel, digest in tree(packet).items()
        if digest not in ("folder",) and rel != manifest_name(provenance)
    }
    if any(d.startswith("link") for d in on_disk.values()):
        return False
    entries = []
    for path in sorted(listed):
        if path in on_disk:
            if on_disk[path] != listed[path]:
                return False
            entries.append((path, on_disk[path]))
        elif path in redacted:
            entries.append((path, listed[path]))
        else:
            return False
    if set(on_disk) - set(listed) or not entries:
        return False
    root = chain_root(entries)
    return bool(root == manifest.get("root_hash") == provenance.get("expected_manifest_root_hash"))


def manifest_name(provenance: dict[str, Any]) -> str:
    """The manifest's name as the verifier reads it: a non-empty string, else the default."""
    name = provenance.get("manifest_file", MANIFEST.name)
    return name if isinstance(name, str) and name else MANIFEST.name


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constant(name: str) -> Any:
    raise ValueError(name)


def ambiguous(kit: Path) -> bool:
    """Whether the kit can be read two ways: a repeated key, NaN or Infinity, or a manifest that
    names one file twice (exactly, or by letter case or Unicode form). A verifier must FAIL such a
    kit even when its bytes match (D1e)."""
    try:
        for path in (kit / PROVENANCE, kit / MANIFEST):
            json.loads(
                path.read_bytes(), object_pairs_hook=_strict_pairs, parse_constant=_no_constant
            )
        files = json.loads((kit / MANIFEST).read_bytes())["files"]
        keys = [unicodedata.normalize("NFC", f["path"]).casefold() for f in files]
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return True
    return len(keys) != len(set(keys))


# --- the mutations --------------------------------------------------------------------------------


class Source(Protocol):
    def randrange(self, start: int, stop: int = ..., /) -> int: ...


def _pick(source: Source, items: list[Any]) -> Any:
    return items[source.randrange(len(items))]


def _files(kit: Path) -> list[Path]:
    """Regular files under ``kit``, reached without following any link."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(kit):
        for name in filenames:
            path = Path(dirpath) / name
            if not is_link(path) and path.is_file():
                found.append(path)
    return sorted(found)


_PATH_TRICKS = [
    "../outside.txt",
    "../../outside.txt",
    "/etc/passwd",
    "C:outside.txt",
    "C:/Windows/win.ini",
    "//localhost/c$/outside.txt",
    "..\\..\\outside.txt",
    "./a",
    "a//b",
    "",
    "AUDIT-CONSISTENCY/RUN_MANIFEST.JSON",
    "caf\u0065\u0301.json",
    "x\nPASS",
    "\u202e",
    "nul",
    "con.json",
]


def _target(source: Source, kit: Path) -> Path:
    """The file a byte-level edit lands on: the two JSON files a third of the time each, since
    they are what the verifier parses, and any file in the kit otherwise."""
    choice = source.randrange(3)
    if choice == 0 and (kit / PROVENANCE).is_file():
        return kit / PROVENANCE
    if choice == 1 and (kit / MANIFEST).is_file():
        return kit / MANIFEST
    target: Path = _pick(source, _files(kit))
    return target


def _flip(source: Source, kit: Path) -> None:
    target = _target(source, kit)
    data = bytearray(target.read_bytes())
    if data:
        index = source.randrange(len(data))
        data[index] ^= 1 << source.randrange(8)
        target.write_bytes(bytes(data))


def _truncate(source: Source, kit: Path) -> None:
    target = _target(source, kit)
    data = target.read_bytes()
    target.write_bytes(data[: source.randrange(len(data) + 1)])


def _insert(source: Source, kit: Path) -> None:
    target = _target(source, kit)
    data = target.read_bytes()
    at = source.randrange(len(data) + 1)
    junk = _pick(source, [b"[", b"{", b'"', b"\\", b"\xff", b"NaN", b"\x00", b',"files":[]', b"]}"])
    target.write_bytes(data[:at] + junk + data[at:])


def _rename(source: Source, kit: Path) -> None:
    packet_files = [p for p in _files(kit / "packet") if p.name != MANIFEST.name]
    if not packet_files:
        return
    target = _pick(source, packet_files)
    new_name = _pick(source, ["renamed.json", target.name.upper(), "integrity_manifest.json", ".x"])
    destination = target.with_name(new_name)
    if not destination.exists():
        target.rename(destination)


def _delete_file(source: Source, kit: Path) -> None:
    packet_files = [p for p in _files(kit / "packet") if p.name != MANIFEST.name]
    if packet_files:
        _pick(source, packet_files).unlink()


def _edit_manifest(source: Source, kit: Path) -> None:
    try:
        manifest = load_manifest(kit)
        files = manifest["files"]
        assert isinstance(files, list) and files
    except (ValueError, KeyError, TypeError, AssertionError, OSError):
        return
    choice = source.randrange(6)
    index = source.randrange(len(files))
    if choice == 0:
        files.append(dict(files[index]))  # a duplicated entry
    elif choice == 1:
        del files[index]  # a deleted entry
    elif choice == 2:
        files[index] = {"path": _pick(source, _PATH_TRICKS), "sha256": files[index].get("sha256")}
    elif choice == 3:
        files[index]["sha256"] = _pick(source, ["0" * 64, "", None, 7, files[0].get("sha256")])
    elif choice == 4:
        manifest["root_hash"] = _pick(source, [None, "", GENESIS, 0, "x" * 64])
    else:
        manifest[_pick(source, ["files", "root_hash", "format_version"])] = _pick(
            source, [None, {}, [], "", 0, [[[]]]]
        )
    reseal = source.randrange(2)
    if reseal and isinstance(manifest.get("files"), list):
        try:
            seal(kit, manifest)
            return
        except (KeyError, TypeError, ValueError):
            pass
    (kit / MANIFEST).write_bytes(json.dumps(manifest).encode("utf-8"))


def _edit_provenance(source: Source, kit: Path) -> None:
    try:
        provenance = json.loads((kit / PROVENANCE).read_bytes())
        assert isinstance(provenance, dict)
    except (ValueError, AssertionError, OSError):
        return
    key = _pick(
        source, ["packet_dir", "manifest_file", "redacted_files", "expected_manifest_root_hash"]
    )
    provenance[key] = _pick(
        source,
        [
            None,
            "",
            "..",
            ".",
            "packet/..",
            "/",
            0,
            [],
            ["snapshot_envelope.json"],
            ["../x"],
            GENESIS,
        ]
        + _PATH_TRICKS,
    )
    (kit / PROVENANCE).write_bytes(json.dumps(provenance).encode("utf-8"))


def _link_trick(source: Source, kit: Path) -> None:
    """A link out of the kit, in one of four places. Skipped where links cannot be made."""
    outside = outside_file(kit)
    choice = source.randrange(4)
    try:
        if choice == 0:
            os.symlink(outside, kit / "packet" / "leak.txt")
        elif choice == 1:
            (kit / PROVENANCE).replace(kit.parent / "provenance-outside.json")
            os.symlink(kit.parent / "provenance-outside.json", kit / PROVENANCE)
        elif choice == 2:
            (kit / MANIFEST).replace(kit.parent / "manifest-outside.json")
            os.symlink(kit.parent / "manifest-outside.json", kit / MANIFEST)
        else:
            os.symlink(kit.parent, kit / "packet" / "up", target_is_directory=True)
    except (OSError, NotImplementedError):
        pass


MUTATIONS: list[Callable[[Source, Path], None]] = [
    _flip,
    _truncate,
    _insert,
    _rename,
    _delete_file,
    _edit_manifest,
    _edit_provenance,
    _link_trick,
]


def mutate(source: Source, kit: Path) -> list[str]:
    """One to three random edits to ``kit``; returns their names, for the failure report."""
    applied = []
    for _ in range(1 + source.randrange(3)):
        mutation = _pick(source, MUTATIONS)
        mutation(source, kit)
        applied.append(mutation.__name__.lstrip("_"))
    return applied


# --- running the verifier in this process, and watching it ------------------------------------
#
# A child process shows what a recipient sees; this shows what the verifier DOES. Through
# ``sys.addaudithook`` the interpreter itself reports every file opened (and its mode), every
# folder listed, every file-system change and every socket event, so nothing in the verifier has
# to cooperate. An audit hook cannot be removed once added, so ``install_audit_hook`` adds one per
# process, and it records only while a run is in progress.

_WRITE_EVENTS = frozenset(
    {
        "os.remove",
        "os.rename",
        "os.replace",
        "os.mkdir",
        "os.rmdir",
        "os.symlink",
        "os.link",
        "os.chmod",
        "os.chown",
        "os.utime",
        "os.truncate",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.move",
        "shutil.rmtree",
    }
)
_LIST_EVENTS = frozenset({"os.scandir", "os.listdir"})


@dataclass
class Watch:
    opened: list[tuple[str, str]] = field(default_factory=list)  # (real path, "read" or "write")
    listed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    network: list[str] = field(default_factory=list)


_watch: Watch | None = None
_hook_installed = False
_INTERPRETER = tuple(
    str(Path(p).resolve()) for p in dict.fromkeys((sys.prefix, sys.base_prefix, sys.exec_prefix))
)


def _real(value: Any) -> str | None:
    if isinstance(value, int):  # a file descriptor, recorded when it was opened
        return None
    try:
        return os.path.realpath(os.fsdecode(value))
    except (TypeError, ValueError):
        return None


def _hook(event: str, args: tuple[Any, ...]) -> None:
    watch = _watch
    if watch is None:
        return
    if event == "open":
        path = _real(args[0])
        if path is not None and not path.startswith(_INTERPRETER):
            mode = args[1] if len(args) > 1 and isinstance(args[1], str) else "r"
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            writes = any(c in mode for c in "wax+") or bool(flags & (os.O_WRONLY | os.O_RDWR))
            watch.opened.append((path, "write" if writes else "read"))
    elif event in _LIST_EVENTS:
        path = _real(args[0]) if args and args[0] is not None else os.getcwd()
        if path is not None:
            watch.listed.append(path)
    elif event in _WRITE_EVENTS:
        watch.changed.append(f"{event} {args[:2]!r}")
    elif event.startswith("socket."):
        watch.network.append(event)


def install_audit_hook() -> None:
    global _hook_installed
    if not _hook_installed:
        sys.addaudithook(_hook)
        _hook_installed = True


def load_verifier(path: Path | None = None) -> ModuleType:
    """``verify.py`` as a module, loaded from its file: it is a script, not a package."""
    target = path or verify_py()
    spec = importlib.util.spec_from_file_location("verify_under_test", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Outcome:
    code: int | None  # None when an exception escaped the verifier
    stdout: str
    escaped: str  # the exception that escaped, as "Type: message", or ""
    watch: Watch


def run_in_process(verifier: ModuleType, kit: Path, *args: str, console: str = "utf-8") -> Outcome:
    """``verifier.main([...])`` on ``kit``, watched, its output written in ``console`` strictly, as
    a real console refuses a character it cannot show."""
    global _watch
    install_audit_hook()
    raw = io.BytesIO()
    out = io.TextIOWrapper(raw, encoding=console, errors="strict", newline="\n")
    err = io.TextIOWrapper(io.BytesIO(), encoding=console, errors="strict", newline="\n")
    code: int | None = None
    escaped = ""
    watch = Watch()
    _watch = watch
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = verifier.main(["verify.py", str(kit), *args])
            except BaseException as exc:  # noqa: BLE001 -- what escapes is the finding itself
                escaped = f"{type(exc).__name__}: {exc}"
    finally:
        _watch = None
    with contextlib.suppress(ValueError, UnicodeError):
        out.flush()
    return Outcome(code, raw.getvalue().decode(console, "backslashreplace"), escaped, watch)


def _inside(path: str, root: Path) -> bool:
    root_real = os.path.realpath(root)
    return path == root_real or path.startswith(root_real + os.sep)


def violations(kit: Path, outcome: Outcome, reason: str | None = None) -> dict[str, list[str]]:
    """What ``outcome`` breaks of D1, keyed by item (a, b, c, e). ``reason``, given, must be named.

    D1d is not judged here: a bound on time or memory is a property of the input's size, and is
    held by the named cases that build a large input.
    """
    found: dict[str, list[str]] = {"a": [], "b": [], "c": [], "e": []}
    if outcome.code == EXIT_PASS and not bytes_match(kit):
        found["a"].append("PASS on a kit whose bytes do not match its manifest and roots")
    for path, mode in outcome.watch.opened:
        if not _inside(path, kit):
            found["b"].append(f"opened outside the kit: {path}")
        if mode == "write":
            found["c"].append(f"opened for writing: {path}")
    for path in outcome.watch.listed:
        if not _inside(path, kit):
            found["b"].append(f"listed a folder outside the kit: {path}")
    found["c"] += [f"changed the file system: {c}" for c in outcome.watch.changed]
    found["c"] += [f"network: {n}" for n in outcome.watch.network]
    if outcome.escaped:
        found["e"].append(f"an exception escaped: {outcome.escaped}")
    elif outcome.code not in (EXIT_PASS, EXIT_FAIL):
        found["e"].append(f"exit code {outcome.code} on a kit (2 is for the command line)")
    lines = outcome.stdout.splitlines()
    if outcome.code == EXIT_FAIL:
        if not lines or lines[0] != FAIL_HEADLINE:
            found["e"].append(f"FAIL without its headline: {lines[:1]}")
        elif len(lines) < 2 or any(not line.startswith("  - ") for line in lines[1:]):
            found["e"].append("a reason is not one line: " + repr(outcome.stdout[:200]))
        if reason is not None and not any(p in outcome.stdout for p in reason.split("|")):
            found["e"].append(f"no reason names {reason!r}: " + repr(outcome.stdout[:200]))
    if outcome.code == EXIT_PASS and ambiguous(kit):
        found["e"].append("PASS on a kit that can be read two ways")
    return {item: items for item, items in found.items() if items}
