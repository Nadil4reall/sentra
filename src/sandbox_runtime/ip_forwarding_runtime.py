"""Fixed procfs backend for 3.3.1 source-state replay in a sandbox guest.

This is not an M5 invocation. No caller can select a file, command, or argv.
The four procfs names below are the complete write allowlist for this backend.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

from src.target_profiler.collectors import CollectionContext, ipv6_enabled
from src.target_profiler.models import FactStatus


_IPV4_FORWARD = "/proc/sys/net/ipv4/ip_forward"
_IPV6_FORWARD = "/proc/sys/net/ipv6/conf/all/forwarding"
_IPV4_ROUTE_FLUSH = "/proc/sys/net/ipv4/route/flush"
_IPV6_ROUTE_FLUSH = "/proc/sys/net/ipv6/route/flush"
_READ_PATHS = frozenset({_IPV4_FORWARD, _IPV6_FORWARD})
_WRITE_PATHS = frozenset({
    _IPV4_FORWARD, _IPV6_FORWARD, _IPV4_ROUTE_FLUSH, _IPV6_ROUTE_FLUSH,
})


def _read_fixed_bit(path: str) -> int:
    if path not in _READ_PATHS:
        raise ValueError("unsupported forwarding observation")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        raw = os.read(descriptor, 16)
    finally:
        os.close(descriptor)
    if raw.strip() not in {b"0", b"1"}:
        raise ValueError("invalid forwarding observation")
    return int(raw.strip())


def _write_fixed_bit(path: str, value: int) -> None:
    if path not in _WRITE_PATHS or type(value) is not int or value not in {0, 1}:
        raise ValueError("unsupported forwarding mutation")
    if sys.platform != "linux" or os.geteuid() != 0:
        raise PermissionError("sandbox forwarding mutation requires Linux root")
    payload = b"1\n" if value else b"0\n"
    flags = os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise OSError("fixed forwarding write was incomplete")
    finally:
        os.close(descriptor)


class SystemForwardingRuntime:
    """Only fixed forwarding keys and route flushes; no arbitrary file API."""

    def ipv6_enabled(self) -> bool:
        observation = ipv6_enabled(CollectionContext(root=Path("/")))
        if observation.status is not FactStatus.COLLECTED or type(observation.value) is not bool:
            raise ValueError("IPv6 availability is unknown")
        return observation.value

    def read_ipv4(self) -> int:
        return _read_fixed_bit(_IPV4_FORWARD)

    def read_ipv6(self) -> int:
        return _read_fixed_bit(_IPV6_FORWARD)

    def set_ipv4(self, value: int) -> None:
        _write_fixed_bit(_IPV4_FORWARD, value)
        _write_fixed_bit(_IPV4_ROUTE_FLUSH, 1)

    def set_ipv6(self, value: int) -> None:
        _write_fixed_bit(_IPV6_FORWARD, value)
        _write_fixed_bit(_IPV6_ROUTE_FLUSH, 1)
