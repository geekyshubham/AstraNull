#!/usr/bin/env python3
"""Atomic, identity-bound PostgreSQL backup retention.

Linux production uses renameat2(RENAME_NOREPLACE) relative to held directory
file descriptors. macOS uses renameatx_np(RENAME_EXCL) only so the same audit
regressions can run locally. There is deliberately no stat+rename fallback.

Linux has no compare-and-unlink-by-inode syscall. After one pair-wide final
barrier, this helper therefore reclaims data only through the two held
O_NOFOLLOW file descriptors and preserves zero-byte quarantine tombstones.
At most MAX_RETENTION_TOMBSTONE_DIRECTORIES are admitted; reaching the cap
fails before a new quarantine is created. Tombstones may be removed only by an
operator while retention is quiesced, never by this race-exposed code path.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import secrets
import stat
import sys
from dataclasses import dataclass
from typing import Any, Callable, Iterable, TextIO

BACKUP_IDENTITY_FIELDS = (
    "dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "nlink"
)
MAX_BACKUP_INVENTORY_ARTIFACTS = 64
MAX_BACKUP_MANIFEST_BYTES = 65_536
MAX_RETENTION_TOMBSTONE_DIRECTORIES = 4_096
QUARANTINE_PREFIX = ".postgres-retention-quarantine-"
CURRENT_BACKUP_ARTIFACT_RE = re.compile(
    r"^postgres-([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2})-([0-9]{2})-([0-9]{2})-([0-9]{3})Z-"
    r"[0-9a-f]{12}\.dump\.enc$"
)
RENAME_NOREPLACE = 1
RENAME_EXCL = 0x00000004


@dataclass(frozen=True)
class BackupRecord:
    name: str
    artifact_identity: tuple[int, ...]
    manifest_identity: tuple[int, ...]


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )


def _is_valid_timestamp(match: re.Match[str]) -> bool:
    year, month, day, hour, minute, second, millisecond = map(int, match.groups())
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return (
        1 <= month <= 12
        and 1 <= day <= days[month - 1]
        and 0 <= hour <= 23
        and 0 <= minute <= 59
        and 0 <= second <= 59
        and 0 <= millisecond <= 999
    )


def _parse_integer(value: str, *, signed: bool) -> int:
    pattern = r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*)"
    if re.fullmatch(pattern, value) is None:
        raise ValueError("backup identity record contains a non-canonical integer")
    return int(value)


def parse_identity_record(raw: str) -> BackupRecord:
    if not isinstance(raw, str) or not raw or len(raw) > 2_048 or "\n" in raw or "\r" in raw:
        raise ValueError("backup identity record must be one bounded line")
    fields = raw.split("\t")
    name_match = CURRENT_BACKUP_ARTIFACT_RE.fullmatch(fields[0]) if fields else None
    if len(fields) != 19 or name_match is None or not _is_valid_timestamp(name_match):
        raise ValueError("backup identity record has an unsafe artifact name or field count")

    def parse_identity(offset: int) -> tuple[int, ...]:
        return tuple(
            _parse_integer(fields[offset + index], signed=field in ("mtime_ns", "ctime_ns"))
            for index, field in enumerate(BACKUP_IDENTITY_FIELDS)
        )

    record = BackupRecord(fields[0], parse_identity(1), parse_identity(10))
    if record.artifact_identity[-1] != 1 or record.manifest_identity[-1] != 1:
        raise ValueError("backup identity record must describe singly linked files")
    return record


def _assert_safe_file(value: os.stat_result, label: str, *, manifest: bool = False,
                      tombstone: bool = False) -> None:
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise RuntimeError(f"unsafe backup {label}: expected a singly linked regular file")
    if manifest and not tombstone and not (1 <= value.st_size <= MAX_BACKUP_MANIFEST_BYTES):
        raise RuntimeError(f"unsafe backup {label}: manifest size is outside the bounded range")
    if tombstone and value.st_size != 0:
        raise RuntimeError(f"unsafe backup {label}: expected a zero-byte retained tombstone")


def _assert_exact_file(value: os.stat_result, expected: tuple[int, ...], label: str,
                       *, manifest: bool = False, tombstone: bool = False) -> None:
    _assert_safe_file(value, label, manifest=manifest, tombstone=tombstone)
    if _identity(value) != expected:
        raise RuntimeError(f"backup {label} identity changed")


def _assert_captured_file(value: os.stat_result, expected: tuple[int, ...], label: str,
                          *, manifest: bool = False) -> tuple[int, ...]:
    _assert_safe_file(value, label, manifest=manifest)
    actual = _identity(value)
    for index, field in enumerate(BACKUP_IDENTITY_FIELDS):
        if field != "ctime_ns" and actual[index] != expected[index]:
            raise RuntimeError(f"backup captured {label} identity changed")
    return actual


def _assert_private_directory(value: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_IMODE(value.st_mode) != 0o700
        or value.st_uid != os.getuid()
    ):
        raise RuntimeError(
            f"unsafe backup {label}: expected a deploy-user-owned mode-0700 directory"
        )


def _assert_directory_handle_matches_stat(
    handle_stat: os.stat_result, path_stat: os.stat_result, label: str
) -> None:
    _assert_private_directory(handle_stat, label)
    _assert_private_directory(path_stat, f"{label} path")
    if _identity(handle_stat) != _identity(path_stat):
        raise RuntimeError(f"backup {label} identity changed")


def _open_directory(path: str) -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, field) for field in required):
        raise RuntimeError("backup retention requires O_NOFOLLOW and O_DIRECTORY support")
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _open_file_at(directory_fd: int, name: str, *, writable: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("backup retention requires O_NOFOLLOW support")
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=directory_fd)


def _atomic_rename_no_replace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Use an OS no-replace rename; never emulate it with a pre-check."""
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(source_name)
    destination = os.fsencode(destination_name)
    if sys.platform.startswith("linux"):
        try:
            rename = libc.renameat2
        except AttributeError as error:
            raise OSError(errno.ENOSYS, "libc does not expose renameat2") from error
        flags = RENAME_NOREPLACE
    elif sys.platform == "darwin":
        try:
            rename = libc.renameatx_np
        except AttributeError as error:
            raise OSError(errno.ENOSYS, "libSystem does not expose renameatx_np") from error
        flags = RENAME_EXCL
    else:
        raise OSError(errno.ENOTSUP, "atomic no-replace rename is unsupported on this platform")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_directory_fd, source, destination_directory_fd, destination, flags) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), destination_name)


Checkpoint = Callable[[str, dict[str, Any]], None]


def _stat_at(directory_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)


def _assert_path_absent_at(directory_fd: int, name: str, label: str) -> None:
    try:
        _stat_at(directory_fd, name)
    except FileNotFoundError:
        return
    raise RuntimeError(f"backup {label} path was replaced after quarantine capture")


def _assert_root_live(root_fd: int, root: str, label: str) -> None:
    _assert_directory_handle_matches_stat(
        os.fstat(root_fd), os.stat(root, follow_symlinks=False), label
    )


def _assert_quarantine_live(root_fd: int, quarantine_fd: int, quarantine_name: str,
                            label: str) -> None:
    _assert_directory_handle_matches_stat(
        os.fstat(quarantine_fd), _stat_at(root_fd, quarantine_name), label
    )


def _sync(checkpoint: Checkpoint, descriptor: int, context: dict[str, Any], phase: str) -> None:
    checkpoint("before_retention_sync", {**context, "phase": phase})
    os.fsync(descriptor)
    checkpoint("retention_sync", {**context, "phase": phase})


def _verify_pair(root_fd: int, record: BackupRecord, checkpoint: Checkpoint, phase: str,
                 context: dict[str, Any]) -> None:
    artifact_fd = manifest_fd = None
    try:
        artifact_fd = _open_file_at(root_fd, record.name, writable=False)
        manifest_fd = _open_file_at(root_fd, f"{record.name}.manifest.json", writable=False)
        _assert_exact_file(os.fstat(artifact_fd), record.artifact_identity,
                           f"artifact {record.name} before {phase}")
        _assert_exact_file(os.fstat(manifest_fd), record.manifest_identity,
                           f"manifest {record.name} before {phase}", manifest=True)
        checkpoint(f"{phase}_handles_opened", context)
        _assert_exact_file(os.fstat(artifact_fd), record.artifact_identity,
                           f"artifact {record.name} during {phase}")
        _assert_exact_file(os.fstat(manifest_fd), record.manifest_identity,
                           f"manifest {record.name} during {phase}", manifest=True)
        _assert_exact_file(_stat_at(root_fd, record.name), record.artifact_identity,
                           f"artifact path {record.name} during {phase}")
        _assert_exact_file(_stat_at(root_fd, f"{record.name}.manifest.json"),
                           record.manifest_identity,
                           f"manifest path {record.name} during {phase}", manifest=True)
    finally:
        for descriptor in (manifest_fd, artifact_fd):
            if descriptor is not None:
                os.close(descriptor)


def _capture(
    *,
    root_fd: int,
    quarantine_fd: int,
    source_name: str,
    captured_name: str,
    expected: tuple[int, ...],
    label: str,
    manifest: bool,
    context: dict[str, Any],
    checkpoint: Checkpoint,
) -> tuple[int, tuple[int, ...]]:
    source_fd = captured_fd = None
    try:
        source_fd = _open_file_at(root_fd, source_name, writable=True)
        _assert_exact_file(os.fstat(source_fd), expected,
                           f"{label} source handle immediately before capture",
                           manifest=manifest)
        _assert_exact_file(_stat_at(root_fd, source_name), expected,
                           f"{label} source path immediately before capture",
                           manifest=manifest)
        checkpoint(f"before_retention_{label}_capture", context)
        _atomic_rename_no_replace(root_fd, source_name, quarantine_fd, captured_name)
        checkpoint(f"retention_{label}_captured", context)

        captured_fd = _open_file_at(quarantine_fd, captured_name, writable=True)
        captured_identity = _assert_captured_file(
            os.fstat(captured_fd), expected, label, manifest=manifest
        )
        _assert_exact_file(_stat_at(quarantine_fd, captured_name), captured_identity,
                           f"{label} quarantine path", manifest=manifest)
        _assert_exact_file(os.fstat(source_fd), captured_identity,
                           f"{label} source handle after capture", manifest=manifest)
        _assert_path_absent_at(root_fd, source_name, label)
        os.close(source_fd)
        source_fd = None
        return captured_fd, captured_identity
    except BaseException:
        for descriptor in (captured_fd, source_fd):
            if descriptor is not None:
                os.close(descriptor)
        raise


def _assert_single_capture_barrier(
    *,
    root_fd: int,
    root: str,
    quarantine_fd: int,
    quarantine_name: str,
    capture_fd: int,
    capture_identity: tuple[int, ...],
    captured_name: str,
    record_name: str,
    label: str,
    manifest: bool,
) -> None:
    _assert_root_live(root_fd, root, f"retention backup root after {label} capture")
    _assert_quarantine_live(
        root_fd,
        quarantine_fd,
        quarantine_name,
        f"retention quarantine {record_name} after {label} capture",
    )
    _assert_exact_file(os.fstat(capture_fd), capture_identity,
                       f"captured {label} held handle after capture", manifest=manifest)
    live_fd = _open_file_at(quarantine_fd, captured_name, writable=False)
    try:
        _assert_exact_file(os.fstat(live_fd), capture_identity,
                           f"captured {label} live handle after capture", manifest=manifest)
        _assert_exact_file(_stat_at(quarantine_fd, captured_name), capture_identity,
                           f"captured {label} live path after capture", manifest=manifest)
    finally:
        os.close(live_fd)


def _assert_pair_final_barrier(
    *,
    root_fd: int,
    root: str,
    quarantine_fd: int,
    quarantine_name: str,
    record_name: str,
    manifest_fd: int,
    manifest_identity: tuple[int, ...],
    artifact_fd: int,
    artifact_identity: tuple[int, ...],
) -> None:
    """One pair-wide barrier; no captured inode is reclaimed before it passes."""
    _assert_root_live(root_fd, root, "retention backup root at final capture barrier")
    _assert_quarantine_live(
        root_fd,
        quarantine_fd,
        quarantine_name,
        f"retention quarantine {record_name} at final capture barrier",
    )
    _assert_exact_file(os.fstat(manifest_fd), manifest_identity,
                       "captured manifest held handle at final capture barrier", manifest=True)
    _assert_exact_file(os.fstat(artifact_fd), artifact_identity,
                       "captured artifact held handle at final capture barrier")
    _assert_exact_file(_stat_at(quarantine_fd, "manifest"), manifest_identity,
                       "captured manifest live path at final capture barrier", manifest=True)
    _assert_exact_file(_stat_at(quarantine_fd, "artifact"), artifact_identity,
                       "captured artifact live path at final capture barrier")


def _assert_pair_tombstones(
    *,
    root_fd: int,
    root: str,
    quarantine_fd: int,
    quarantine_name: str,
    record_name: str,
    manifest_fd: int,
    artifact_fd: int,
) -> None:
    _assert_root_live(root_fd, root, "retention backup root after inode reclamation")
    _assert_quarantine_live(
        root_fd,
        quarantine_fd,
        quarantine_name,
        f"retention quarantine {record_name} after inode reclamation",
    )
    manifest_identity = _identity(os.fstat(manifest_fd))
    artifact_identity = _identity(os.fstat(artifact_fd))
    _assert_exact_file(os.fstat(manifest_fd), manifest_identity,
                       "captured manifest held tombstone", manifest=True, tombstone=True)
    _assert_exact_file(os.fstat(artifact_fd), artifact_identity,
                       "captured artifact held tombstone", tombstone=True)
    _assert_exact_file(_stat_at(quarantine_fd, "manifest"), manifest_identity,
                       "captured manifest live tombstone", manifest=True, tombstone=True)
    _assert_exact_file(_stat_at(quarantine_fd, "artifact"), artifact_identity,
                       "captured artifact live tombstone", tombstone=True)


def _validate_tombstone_budget(root_fd: int, requested: int) -> None:
    tombstones = sorted(name for name in os.listdir(root_fd) if name.startswith(QUARANTINE_PREFIX))
    if len(tombstones) + requested > MAX_RETENTION_TOMBSTONE_DIRECTORIES:
        raise RuntimeError(
            "backup retention tombstone directory limit "
            f"{MAX_RETENTION_TOMBSTONE_DIRECTORIES} would be exceeded"
        )
    for name in tombstones:
        _assert_private_directory(_stat_at(root_fd, name), f"retention tombstone {name}")


def _create_quarantine(root_fd: int) -> tuple[str, int]:
    for _ in range(16):
        name = f"{QUARANTINE_PREFIX}{secrets.token_hex(12)}"
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            continue
        quarantine_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        os.fchmod(quarantine_fd, 0o700)
        return name, quarantine_fd
    raise RuntimeError("backup retention could not allocate a unique quarantine directory")


def _prune_record(root: str, root_fd: int, record: BackupRecord,
                  checkpoint: Checkpoint) -> None:
    artifact_name = record.name
    manifest_name = f"{record.name}.manifest.json"
    quarantine_name, quarantine_fd = _create_quarantine(root_fd)
    quarantine_path = os.path.join(root, quarantine_name)
    context = {
        "name": record.name,
        "artifactPath": os.path.join(root, artifact_name),
        "manifestPath": os.path.join(root, manifest_name),
        "quarantinePath": quarantine_path,
        "capturedArtifactPath": os.path.join(quarantine_path, "artifact"),
        "capturedManifestPath": os.path.join(quarantine_path, "manifest"),
    }
    manifest_fd = artifact_fd = None
    try:
        _assert_directory_handle_matches_stat(
            os.fstat(quarantine_fd),
            _stat_at(root_fd, quarantine_name),
            f"retention quarantine {record.name}",
        )
        if os.fstat(quarantine_fd).st_dev != os.fstat(root_fd).st_dev:
            raise RuntimeError(
                f"backup retention quarantine is not on the backup filesystem: {record.name}"
            )
        _sync(checkpoint, quarantine_fd, context, "quarantine_create_quarantine")
        _sync(checkpoint, root_fd, context, "quarantine_create_root")
        checkpoint("retention_quarantine_created", context)

        manifest_fd, manifest_identity = _capture(
            root_fd=root_fd,
            quarantine_fd=quarantine_fd,
            source_name=manifest_name,
            captured_name="manifest",
            expected=record.manifest_identity,
            label="manifest",
            manifest=True,
            context=context,
            checkpoint=checkpoint,
        )
        _assert_single_capture_barrier(
            root_fd=root_fd,
            root=root,
            quarantine_fd=quarantine_fd,
            quarantine_name=quarantine_name,
            capture_fd=manifest_fd,
            capture_identity=manifest_identity,
            captured_name="manifest",
            record_name=record.name,
            label="manifest",
            manifest=True,
        )
        _sync(checkpoint, quarantine_fd, context, "manifest_quarantine")
        _sync(checkpoint, root_fd, context, "manifest_root")
        checkpoint("retention_manifest_public_removal_durable", context)

        artifact_fd, artifact_identity = _capture(
            root_fd=root_fd,
            quarantine_fd=quarantine_fd,
            source_name=artifact_name,
            captured_name="artifact",
            expected=record.artifact_identity,
            label="artifact",
            manifest=False,
            context=context,
            checkpoint=checkpoint,
        )
        _assert_single_capture_barrier(
            root_fd=root_fd,
            root=root,
            quarantine_fd=quarantine_fd,
            quarantine_name=quarantine_name,
            capture_fd=artifact_fd,
            capture_identity=artifact_identity,
            captured_name="artifact",
            record_name=record.name,
            label="artifact",
            manifest=False,
        )
        _sync(checkpoint, quarantine_fd, context, "artifact_quarantine")
        _sync(checkpoint, root_fd, context, "artifact_root")
        checkpoint("retention_artifact_public_removal_durable", context)

        checkpoint("before_retention_final_capture_barrier", context)
        _assert_pair_final_barrier(
            root_fd=root_fd,
            root=root,
            quarantine_fd=quarantine_fd,
            quarantine_name=quarantine_name,
            record_name=record.name,
            manifest_fd=manifest_fd,
            manifest_identity=manifest_identity,
            artifact_fd=artifact_fd,
            artifact_identity=artifact_identity,
        )
        # This checkpoint intentionally exposes the exact post-lstat race to tests.
        # Subsequent operations are identity-bound to held descriptors; no pathname is unlinked.
        checkpoint("retention_final_capture_barrier_complete", context)

        os.ftruncate(manifest_fd, 0)
        os.fsync(manifest_fd)
        checkpoint("retention_captured_manifest_reclaimed", context)
        os.ftruncate(artifact_fd, 0)
        os.fsync(artifact_fd)
        checkpoint("retention_captured_artifact_reclaimed", context)

        _assert_pair_tombstones(
            root_fd=root_fd,
            root=root,
            quarantine_fd=quarantine_fd,
            quarantine_name=quarantine_name,
            record_name=record.name,
            manifest_fd=manifest_fd,
            artifact_fd=artifact_fd,
        )
        _sync(checkpoint, quarantine_fd, context, "retained_tombstones_quarantine")
        _sync(checkpoint, root_fd, context, "retained_tombstones_root")
        checkpoint("retention_tombstones_durable", context)
    finally:
        for descriptor in (artifact_fd, manifest_fd, quarantine_fd):
            if descriptor is not None:
                os.close(descriptor)


def prune(root: str, raw_records: Iterable[str], checkpoint: Checkpoint) -> dict[str, Any]:
    records = [parse_identity_record(raw) for raw in raw_records]
    if len(records) > MAX_BACKUP_INVENTORY_ARTIFACTS:
        raise ValueError("backup retention identity record set is invalid or unbounded")
    names = [record.name for record in records]
    if len(set(names)) != len(names):
        raise ValueError("backup retention identity record set contains duplicate names")
    if not os.path.isabs(root):
        raise ValueError("backup retention root must be an absolute path")

    root_fd = _open_directory(root)
    try:
        _assert_root_live(root_fd, root, "retention backup root")
        _validate_tombstone_budget(root_fd, len(records))
        for record in records:
            context = {
                "name": record.name,
                "artifactPath": os.path.join(root, record.name),
                "manifestPath": os.path.join(root, f"{record.name}.manifest.json"),
            }
            _verify_pair(root_fd, record, checkpoint, "retention_preflight", context)
        checkpoint("retention_preflight_complete", {"recordNames": names})
        for record in records:
            context = {
                "name": record.name,
                "artifactPath": os.path.join(root, record.name),
                "manifestPath": os.path.join(root, f"{record.name}.manifest.json"),
            }
            _verify_pair(root_fd, record, checkpoint, "retention_delete", context)
            checkpoint("before_retention_delete", context)
            _prune_record(root, root_fd, record, checkpoint)
    finally:
        os.close(root_fd)
    return {
        "ok": True,
        "pruned": names,
        "maxTombstoneDirectories": MAX_RETENTION_TOMBSTONE_DIRECTORIES,
        "primitive": "renameat2(RENAME_NOREPLACE)" if sys.platform.startswith("linux")
        else "renameatx_np(RENAME_EXCL)",
    }


class ProtocolCheckpoint:
    def __init__(self, source: TextIO, destination: TextIO) -> None:
        self.source = source
        self.destination = destination

    def __call__(self, step: str, context: dict[str, Any]) -> None:
        self.destination.write(json.dumps({
            "type": "checkpoint", "step": step, "context": context
        }, separators=(",", ":")) + "\n")
        self.destination.flush()
        acknowledgement = self.source.readline()
        if not acknowledgement:
            raise RuntimeError("retention protocol closed before checkpoint acknowledgement")
        parsed = json.loads(acknowledgement)
        if parsed != {"continue": True}:
            raise RuntimeError("retention protocol aborted at checkpoint")


def _error_code(error: BaseException) -> str | None:
    if isinstance(error, OSError) and error.errno is not None:
        return errno.errorcode.get(error.errno, f"ERRNO_{error.errno}")
    return None


def _run_protocol() -> int:
    try:
        request_line = sys.stdin.readline()
        if not request_line:
            raise ValueError("retention protocol request is required")
        request = json.loads(request_line)
        if request.get("maxTombstoneDirectories") != MAX_RETENTION_TOMBSTONE_DIRECTORIES:
            raise ValueError("retention protocol tombstone bound mismatch")
        result = prune(
            os.path.abspath(request["root"]),
            request["identityRecords"],
            ProtocolCheckpoint(sys.stdin, sys.stdout),
        )
        sys.stdout.write(json.dumps({"type": "result", **result}, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 0
    except BaseException as error:  # Protocol must turn every failure into a bounded response.
        sys.stdout.write(json.dumps({
            "type": "error",
            "message": str(error),
            "code": _error_code(error),
        }, separators=(",", ":")) + "\n")
        sys.stdout.flush()
        return 1


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", action="store_true")
    parser.add_argument("--root")
    parser.add_argument("identity_records", nargs="*")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    if args.protocol:
        return _run_protocol()
    if not args.root:
        raise SystemExit("postgres-retention-helper: --root is required")
    try:
        result = prune(os.path.abspath(args.root), args.identity_records, lambda _step, _context: None)
    except BaseException as error:
        code = _error_code(error)
        prefix = f"{code}: " if code else ""
        print(f"postgres-retention-helper: {prefix}{error}", file=sys.stderr)
        return 1
    print(
        "postgres-retention-helper: ok "
        f"({len(result['pruned'])} pair(s), {result['primitive']}, "
        f"tombstone cap {result['maxTombstoneDirectories']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
