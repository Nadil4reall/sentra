"""Serialize M8's explicit profile-job button across web worker processes.

The lock is not workflow state. The Controller jobs table remains authoritative.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
from typing import Iterator


@contextmanager
def _creation_lock(database: Path, suffix: str) -> Iterator[None]:
    parent = os.lstat(database.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise OSError("Controller database parent is not protected")
    path = database.with_name(database.name + suffix)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        linked = os.lstat(path)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)):
            raise OSError("Controller action lock is not protected")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def profile_creation_lock(database: Path):
    return _creation_lock(database, ".m8-profile.lock")


def enforcement_creation_lock(database: Path):
    return _creation_lock(database, ".m8-enforcement.lock")


def analysis_creation_lock(database: Path):
    return _creation_lock(database, ".m8-analysis.lock")
