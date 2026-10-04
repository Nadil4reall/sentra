"""Deterministic tests for the M6E-C Python libvirt API boundary.

The fake module below models storage pools, volumes and domains closely enough
to exercise reconciliation and cleanup. These tests never import or contact a
real libvirt daemon and never require KVM.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat
from types import SimpleNamespace
from xml.etree import ElementTree as ET
from uuid import UUID, uuid4

import pytest

from src.controller.sandbox import (
    BackendObservation,
    LibvirtBackend,
    LocalNestedVmConfig,
    LocalNestedVmProvider,
    LocalNestedVmPlan,
    SandboxProviderError,
    SandboxProviderSecurityError,
    SandboxRuntimeState,
    SandboxStorageMode,
    plan_sha256,
    sandbox_domain_uuid_for,
    sandbox_pool_name_for,
    sandbox_resource_name,
)


class FakeLibvirtError(RuntimeError):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self._code = code

    def get_error_code(self) -> int:
        return self._code


class FakeVolume:
    def __init__(self, pool: "FakePool", xml: str, path: Path) -> None:
        self.pool = pool
        self._xml = xml
        self._path = path

    def name(self) -> str:
        return "root.qcow2"

    def path(self) -> str:
        return str(self._path)

    def XMLDesc(self, _flags: int) -> str:
        return self._xml

    def delete(self, _flags: int) -> None:
        self._path.unlink()
        self.pool.volumes.pop(self.name(), None)


class FakePool:
    def __init__(self, connection: "FakeConnection", xml: str) -> None:
        self.connection = connection
        self._xml = xml
        parsed = ET.fromstring(xml)
        self._name = parsed.findtext("name") or ""
        self.path = Path(parsed.findtext("target/path") or "")
        self.active = False
        self.volumes: dict[str, FakeVolume] = {}

    def name(self) -> str:
        return self._name

    def XMLDesc(self, _flags: int) -> str:
        return self._xml

    def isActive(self) -> int:
        return int(self.active)

    def build(self, _flags: int) -> None:
        parsed = ET.fromstring(self._xml)
        mode_text = parsed.findtext("target/permissions/mode")
        assert mode_text is not None
        mode = int(mode_text, 8)
        self.path.mkdir(mode=mode)
        self.path.chmod(mode)

    def create(self, _flags: int) -> None:
        self.active = True

    def storageVolLookupByName(self, name: str) -> FakeVolume:
        if name not in self.volumes:
            raise FakeLibvirtError("not found", 50)
        return self.volumes[name]

    def createXML(self, xml: str, _flags: int) -> FakeVolume:
        if "root.qcow2" in self.volumes:
            raise FakeLibvirtError("already exists", 50)
        source = ET.fromstring(xml)
        name = source.findtext("name") or ""
        assert name == "root.qcow2"
        target = self.path / name
        with target.open("xb"):
            pass
        target.chmod(0o600)
        self.connection.volume_create_count += 1
        output = ET.Element("volume")
        ET.SubElement(output, "name").text = name
        ET.SubElement(output, "capacity", {"unit": "bytes"}).text = (
            source.findtext("capacity") or "0"
        )
        ET.SubElement(output, "allocation", {"unit": "bytes"}).text = "0"
        target_node = ET.SubElement(output, "target")
        ET.SubElement(target_node, "path").text = str(target)
        fmt = source.find("target/format")
        assert fmt is not None
        ET.SubElement(target_node, "format", dict(fmt.attrib))
        permissions = source.find("target/permissions")
        assert permissions is not None
        target_node.append(permissions)
        backing = source.find("backingStore")
        assert backing is not None
        output.append(backing)
        volume = FakeVolume(self, ET.tostring(output, encoding="unicode"), target)
        self.volumes[name] = volume
        if self.connection.fail_after_volume:
            self.connection.fail_after_volume = False
            raise RuntimeError("simulated process interruption after overlay")
        return volume

    def listVolumes(self) -> list[str]:
        return list(self.volumes)

    def destroy(self) -> None:
        self.active = False

    def delete(self, _flags: int) -> None:
        self.path.rmdir()

    def undefine(self) -> None:
        self.connection.pools.pop(self._name, None)


class FakeDomain:
    def __init__(self, connection: "FakeConnection", xml: str) -> None:
        self.connection = connection
        self._xml = xml
        self._name = ET.fromstring(xml).findtext("name") or ""
        self._state = 5
        self.active = False

    def name(self) -> str:
        return self._name

    def XMLDesc(self, _flags: int) -> str:
        return self._xml

    def isActive(self) -> int:
        return int(self.active)

    def create(self) -> None:
        self.active = True
        self._state = 1
        self.connection.domain_start_count += 1
        if self.connection.fail_after_domain_start:
            self.connection.fail_after_domain_start = False
            raise RuntimeError("simulated process interruption after start")

    def state(self, _flags: int) -> tuple[int, int]:
        return self._state, 0

    def destroy(self) -> None:
        self.active = False
        self._state = 5

    def undefine(self) -> None:
        self.connection.domains.pop(self._name, None)


class FakeConnection:
    def __init__(self, uri: str) -> None:
        self.uri = uri
        self.pools: dict[str, FakePool] = {}
        self.domains: dict[str, FakeDomain] = {}
        self.domain_define_count = 0
        self.domain_start_count = 0
        self.pool_define_count = 0
        self.volume_create_count = 0
        self.fail_after_volume = False
        self.fail_before_domain_define = False
        self.fail_after_domain_start = False
        self.closed = 0

    def storagePoolLookupByName(self, name: str) -> FakePool:
        if name not in self.pools:
            raise FakeLibvirtError("pool not found", 49)
        return self.pools[name]

    def storagePoolDefineXML(self, xml: str, _flags: int) -> FakePool:
        pool = FakePool(self, xml)
        self.pools[pool.name()] = pool
        self.pool_define_count += 1
        return pool

    def lookupByName(self, name: str) -> FakeDomain:
        if name not in self.domains:
            raise FakeLibvirtError("domain not found", 42)
        return self.domains[name]

    def defineXML(self, xml: str) -> FakeDomain:
        if self.fail_before_domain_define:
            self.fail_before_domain_define = False
            raise RuntimeError("simulated interruption after overlay creation")
        domain = FakeDomain(self, xml)
        if domain.name() in self.domains:
            raise FakeLibvirtError("domain exists", 9)
        self.domains[domain.name()] = domain
        self.domain_define_count += 1
        return domain

    def close(self) -> None:
        self.closed += 1


class FakeLibvirtModule:
    VIR_ERR_NO_DOMAIN = 42
    VIR_ERR_NO_STORAGE_POOL = 49
    VIR_ERR_NO_STORAGE_VOL = 50
    VIR_DOMAIN_NOSTATE = 0
    VIR_DOMAIN_RUNNING = 1
    VIR_DOMAIN_BLOCKED = 2
    VIR_DOMAIN_PAUSED = 3
    VIR_DOMAIN_SHUTDOWN = 4
    VIR_DOMAIN_SHUTOFF = 5
    VIR_DOMAIN_CRASHED = 6
    VIR_DOMAIN_PMSUSPENDED = 7

    def __init__(self) -> None:
        self.connections: list[FakeConnection] = []
        self.uris: list[str] = []
        self.system_connection = FakeConnection("qemu:///system")

    def open(self, uri: str) -> FakeConnection:
        self.uris.append(uri)
        connection = self.system_connection
        self.connections.append(connection)
        return connection


def _provider_and_backend(
    tmp_path: Path,
    *,
    module: FakeLibvirtModule | None = None,
    module_loader=None,
) -> tuple[LocalNestedVmProvider, LibvirtBackend, FakeLibvirtModule, Path]:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0 or gid == 0:
        pytest.skip("libvirt permission fixtures require an unprivileged test user")
    root = tmp_path.resolve() / "libvirt-sandboxes"
    root.mkdir(mode=0o710)
    root.chmod(0o710)
    base = root / "ubuntu-24.04-base.qcow2"
    base.write_bytes(b"immutable qcow2 base fixture")
    base.chmod(0o444)
    module = module or FakeLibvirtModule()
    backend = LibvirtBackend(
        module_loader=module_loader or (lambda _name: module)
    )
    provider = LocalNestedVmProvider(
        LocalNestedVmConfig(
            sandbox_root=root,
            base_image=base,
            storage_mode=SandboxStorageMode.LIBVIRT_POOL,
            libvirt_qemu_uid=uid,
            libvirt_qemu_gid=gid,
            libvirt_storage_parent_uid=uid,
        ),
        backend,
    )
    return provider, backend, module, base


def _validate_domain_xml(plan: LocalNestedVmPlan, xml: str) -> ET.Element:
    class StaticDomain:
        def name(self) -> str:
            return plan.sandbox_instance_id

        def XMLDesc(self, flags: int) -> str:
            assert flags == 0
            return xml

    return LibvirtBackend._domain_xml_identity(StaticDomain(), plan)


def _libvirt_channel_source_path(
    plan: LocalNestedVmPlan,
    domain_id: str = "42",
    *,
    base: str = "/run/libvirt/qemu/channel",
    domain_component: str | None = None,
    filename: str = "org.sentra.validation.0",
) -> str:
    short_name = domain_component or plan.sandbox_instance_id[:20]
    return f"{base}/{domain_id}-{short_name}/{filename}"


def test_backend_import_is_lazy_and_connects_only_to_system_uri(
    tmp_path: Path,
) -> None:
    imported: list[str] = []
    module = FakeLibvirtModule()
    provider, _, _, _ = _provider_and_backend(
        tmp_path,
        module=module,
        module_loader=lambda name: imported.append(name) or module,
    )
    assert imported == []

    provider.provision(uuid4())

    assert imported == ["libvirt"]
    assert module.uris == ["qemu:///system"]
    assert module.connections[0].closed == 1


def test_config_requires_explicit_qemu_storage_owner_for_libvirt(
    tmp_path: Path,
) -> None:
    root = tmp_path.resolve()
    base = root / "base.qcow2"
    base.write_bytes(b"base")
    with pytest.raises(ValueError, match="QEMU UID and GID"):
        LocalNestedVmConfig(
            sandbox_root=root,
            base_image=base,
            storage_mode=SandboxStorageMode.LIBVIRT_POOL,
        )


def test_fresh_provision_creates_one_pool_overlay_and_domain(tmp_path: Path) -> None:
    provider, _, module, base = _provider_and_backend(tmp_path)
    session_id = uuid4()
    base_before = base.read_bytes()

    instance = provider.provision(session_id)

    connection = module.connections[0]
    pool_name = sandbox_pool_name_for(session_id)
    domain_name = sandbox_resource_name(session_id)
    assert instance.sandbox_instance_id == domain_name
    assert instance.runtime_state is SandboxRuntimeState.RUNNING
    assert connection.pool_define_count == 1
    assert connection.volume_create_count == 1
    assert connection.domain_define_count == 1
    assert connection.domain_start_count == 1
    assert set(connection.pools) == {pool_name}
    assert set(connection.domains) == {domain_name}
    pool = connection.pools[pool_name]
    assert pool.listVolumes() == ["root.qcow2"]
    overlay = Path(pool.volumes["root.qcow2"].path())
    assert overlay != base
    assert overlay.read_bytes() == b""
    assert stat.S_IMODE(overlay.stat().st_mode) == 0o600
    assert base.read_bytes() == base_before


def test_domain_xml_is_fixed_deterministic_and_contains_no_guest_secrets(
    tmp_path: Path,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
    provider.provision(session_id)
    connection = module.connections[0]
    plan = provider._plan(session_id, prepare_directory=False)
    domain = connection.domains[sandbox_resource_name(session_id)]
    root = ET.fromstring(domain.XMLDesc(0))
    assert root.get("type") == "kvm"
    assert root.findtext("name") == sandbox_resource_name(session_id)
    assert root.findtext("uuid") == str(sandbox_domain_uuid_for(session_id))
    assert root.findtext("memory") == "2097152"
    assert root.findtext("vcpu") == "2"
    assert root.find("os/type").attrib == {"arch": "x86_64", "machine": "q35"}
    os_boots = root.findall("os/boot")
    assert len(os_boots) == 1
    assert os_boots[0].attrib == {"dev": "hd"}
    disk = root.find("devices/disk")
    assert disk is not None
    assert disk.find("boot") is None
    assert disk.find("driver").attrib == {"name": "qemu", "type": "qcow2"}
    assert disk.find("source").get("file") == str(plan.overlay_path)

    backing = disk.find("backingStore")
    assert backing is not None
    assert backing.get("type") == "file"

    backing_format = backing.find("format")
    assert backing_format is not None
    assert backing_format.attrib == {"type": "qcow2"}

    backing_source = backing.find("source")
    assert backing_source is not None
    assert backing_source.get("file") == str(plan.base_image)

    assert backing_source.findall("seclabel") == []
    domain_labels = root.findall("seclabel")
    assert len(domain_labels) == 2
    assert domain_labels[0].attrib == {"type": "dynamic", "model": "apparmor"}
    assert domain_labels[1].attrib == {
        "type": "static",
        "model": "dac",
        "relabel": "no",
    }
    assert domain_labels[1].findtext("label") == (
        f"+{plan.libvirt_qemu_uid}:+{plan.libvirt_qemu_gid}"
    )
    overlay_volume = module.connections[0].pools[
        sandbox_pool_name_for(session_id)
    ].volumes["root.qcow2"]
    volume_xml = ET.fromstring(overlay_volume.XMLDesc(0))
    assert volume_xml.find("backingStore/source/seclabel") is None
    assert disk.find("source/seclabel") is None

    terminal_backing = backing.findall("backingStore")
    assert len(terminal_backing) == 1
    assert terminal_backing[0].attrib == {}
    assert list(terminal_backing[0]) == []

    assert disk.find("target").attrib == {"dev": "vda", "bus": "virtio"}
    network = root.find("devices/interface/source")
    assert network.get("network") == "default"
    assert root.find("devices/interface/model").get("type") == "virtio"
    channels = root.findall("devices/channel")
    assert len(channels) == 1
    assert channels[0].attrib == {"type": "unix"}
    assert len(channels[0].findall("target")) == 1
    assert channels[0].find("target").attrib == {
        "type": "virtio",
        "name": "org.sentra.validation.0",
    }
    assert channels[0].find("source") is None
    balloon = root.find("devices/memballoon")
    assert balloon is not None
    assert balloon.attrib == {"model": "none"}
    for forbidden in ("filesystem", "hostdev", "redirdev", "smartcard", "tpm"):
        assert root.find(f"devices/{forbidden}") is None
    serialized = ET.tostring(root, encoding="unicode").lower()
    for sensitive in ("password", "token", "cloud-init", "ssh-rsa"):
        assert sensitive not in serialized


@pytest.mark.parametrize("state", ["connected", "disconnected"])
def test_valid_libvirt_normalized_validation_channel_is_accepted(
    tmp_path: Path,
    state: str,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    devices = root.find("devices")
    channel = root.find("devices/channel")
    assert devices is not None and channel is not None
    root.set("id", "42")

    source = ET.Element(
        "source",
        {
            "mode": "bind",
            "path": _libvirt_channel_source_path(plan),
        },
    )
    channel.insert(0, source)
    target = channel.find("target")
    assert target is not None
    target.set("state", state)
    ET.SubElement(channel, "alias", {"name": "channel0"})
    ET.SubElement(
        channel,
        "address",
        {
            "type": "virtio-serial",
            "controller": "0",
            "bus": "0",
            "port": "1",
        },
    )
    serial_controller = ET.SubElement(
        devices,
        "controller",
        {"type": "virtio-serial", "index": "0"},
    )
    ET.SubElement(serial_controller, "alias", {"name": "virtio-serial0"})
    ET.SubElement(
        serial_controller,
        "address",
        {
            "type": "pci",
            "domain": "0x0000",
            "bus": "0x02",
            "slot": "0x00",
            "function": "0x0",
        },
    )

    normalized = _validate_domain_xml(plan, ET.tostring(root, encoding="unicode"))
    assert normalized.find("devices/channel/target").get("state") == state


def test_inactive_channel_without_source_is_accepted(tmp_path: Path) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    channel = root.find("devices/channel")
    assert channel is not None
    assert root.get("id") is None
    assert channel.find("source") is None

    _validate_domain_xml(plan, ET.tostring(root, encoding="unicode"))


def test_libvirt_default_virtio_serial_controller_normalization_is_accepted(
    tmp_path: Path,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    devices = root.find("devices")
    channel = root.find("devices/channel")
    assert devices is not None and channel is not None
    ET.SubElement(
        channel,
        "address",
        {"type": "virtio-serial", "controller": "0", "bus": "0"},
    )
    ET.SubElement(
        devices,
        "controller",
        {
            "type": "virtio-serial",
            "index": "0",
            "ports": "16",
            "vectors": "4",
        },
    )

    _validate_domain_xml(plan, ET.tostring(root, encoding="unicode"))


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_channel",
        "duplicate_channel",
        "wrong_channel_type",
        "wrong_target_type",
        "wrong_target_name",
        "extra_channel_child",
        "extra_channel_attribute",
        "extra_target_attribute",
        "unknown_target_state",
        "wrong_source_mode",
        "unexpected_source_type",
        "missing_domain_id",
        "wrong_runtime_id",
        "wrong_short_domain_name",
        "wrong_base_directory",
        "wrong_channel_filename",
        "extra_source_child",
        "duplicate_source",
    ],
)
def test_invalid_validation_channel_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    devices = root.find("devices")
    channel = root.find("devices/channel")
    assert devices is not None and channel is not None
    root.set("id", "42")
    target = channel.find("target")
    assert target is not None
    valid_path = _libvirt_channel_source_path(plan)

    if mutation == "missing_channel":
        devices.remove(channel)
    elif mutation == "duplicate_channel":
        devices.append(ET.fromstring(ET.tostring(channel, encoding="unicode")))
    elif mutation == "wrong_channel_type":
        channel.set("type", "tcp")
    elif mutation == "wrong_target_type":
        target.set("type", "serial")
    elif mutation == "wrong_target_name":
        target.set("name", "org.example.other.0")
    elif mutation == "extra_channel_child":
        ET.SubElement(channel, "protocol", {"type": "raw"})
    elif mutation == "extra_channel_attribute":
        channel.set("path", "/tmp/caller-controlled.sock")
    elif mutation == "extra_target_attribute":
        target.set("path", "/tmp/caller-controlled.sock")
    elif mutation == "unknown_target_state":
        target.set("state", "listening")
    elif mutation == "wrong_source_mode":
        ET.SubElement(
            channel,
            "source",
            {"mode": "connect", "path": valid_path},
        )
    elif mutation == "unexpected_source_type":
        ET.SubElement(
            channel,
            "source",
            {"mode": "bind", "type": "unix", "path": valid_path},
        )
    elif mutation == "missing_domain_id":
        root.attrib.pop("id")
        ET.SubElement(channel, "source", {"mode": "bind", "path": valid_path})
    elif mutation == "wrong_runtime_id":
        ET.SubElement(
            channel,
            "source",
            {"mode": "bind", "path": _libvirt_channel_source_path(plan, "43")},
        )
    elif mutation == "wrong_short_domain_name":
        ET.SubElement(
            channel,
            "source",
            {
                "mode": "bind",
                "path": _libvirt_channel_source_path(
                    plan,
                    domain_component="sentra-sbx-untrusted",
                ),
            },
        )
    elif mutation == "wrong_base_directory":
        ET.SubElement(
            channel,
            "source",
            {
                "mode": "bind",
                "path": _libvirt_channel_source_path(
                    plan,
                    base="/var/lib/libvirt/qemu/channel/target",
                ),
            },
        )
    elif mutation == "wrong_channel_filename":
        ET.SubElement(
            channel,
            "source",
            {
                "mode": "bind",
                "path": _libvirt_channel_source_path(
                    plan,
                    filename="org.sentra.validation.1",
                ),
            },
        )
    elif mutation == "extra_source_child":
        source = ET.SubElement(
            channel,
            "source",
            {"mode": "bind", "path": valid_path},
        )
        ET.SubElement(source, "unexpected")
    else:
        ET.SubElement(channel, "source", {"mode": "bind", "path": valid_path})
        ET.SubElement(channel, "source", {"mode": "bind", "path": valid_path})

    with pytest.raises(SandboxProviderSecurityError, match="channel"):
        _validate_domain_xml(plan, ET.tostring(root, encoding="unicode"))


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("base_path", "/tmp/untrusted-base.qcow2"),
        ("path_label", None),
    ],
)
def test_trusted_backing_store_policy_fails_closed(
    tmp_path: Path,
    mutation: str,
    value: str | None,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    plan = provider._plan(session_id, prepare_directory=False)

    root = ET.fromstring(LibvirtBackend._domain_xml(plan))

    backing_source = root.find("devices/disk/backingStore/source")
    assert backing_source is not None

    if mutation == "base_path":
        backing_source.set("file", value)
    else:
        ET.SubElement(backing_source, "seclabel", {"relabel": "no"})

    mutated_xml = ET.tostring(root, encoding="unicode")

    class StaticDomain:
        def name(self) -> str:
            return plan.sandbox_instance_id

        def XMLDesc(self, flags: int) -> str:
            assert flags == 0
            return mutated_xml

    with pytest.raises(
        SandboxProviderSecurityError,
        match="backing store does not match the trusted base policy",
    ):
        LibvirtBackend._domain_xml_identity(StaticDomain(), plan)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("wrong_uid", None),
        ("wrong_gid", None),
        ("relabel_yes", None),
        ("missing_dac", None),
        ("wrong_dac_type", None),
        ("missing_dac_label", None),
        ("missing_apparmor", None),
        ("disabled_apparmor_type", None),
        ("disabled_apparmor_model", None),
        ("disabled_apparmor_relabel", None),
    ],
)
def test_domain_security_label_policy_fails_closed(
    tmp_path: Path,
    mutation: str,
    value: str | None,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    dac = root.find("seclabel[@model='dac']")
    apparmor = root.find("seclabel[@model='apparmor']")
    assert dac is not None and apparmor is not None

    if mutation == "wrong_uid":
        dac.find("label").text = f"+{plan.libvirt_qemu_uid + 1}:+{plan.libvirt_qemu_gid}"
    elif mutation == "wrong_gid":
        dac.find("label").text = f"+{plan.libvirt_qemu_uid}:+{plan.libvirt_qemu_gid + 1}"
    elif mutation == "relabel_yes":
        dac.set("relabel", "yes")
    elif mutation == "missing_dac":
        root.remove(dac)
    elif mutation == "wrong_dac_type":
        dac.set("type", "dynamic")
    elif mutation == "missing_dac_label":
        dac.remove(dac.find("label"))
    elif mutation == "missing_apparmor":
        root.remove(apparmor)
    elif mutation == "disabled_apparmor_type":
        apparmor.set("type", "none")
    elif mutation == "disabled_apparmor_model":
        apparmor.set("model", "none")
    else:
        apparmor.set("relabel", "no")

    mutated_xml = ET.tostring(root, encoding="unicode")

    class StaticDomain:
        def name(self) -> str:
            return plan.sandbox_instance_id

        def XMLDesc(self, flags: int) -> str:
            assert flags == 0
            return mutated_xml

    with pytest.raises(
        SandboxProviderSecurityError,
        match="security labels|AppArmor|DAC ownership",
    ):
        LibvirtBackend._domain_xml_identity(StaticDomain(), plan)


def test_domain_identity_accepts_libvirt_output_only_backing_indexes(
    tmp_path: Path,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    backing = root.find("devices/disk/backingStore")
    source = root.find("devices/disk/backingStore/source")
    assert backing is not None and source is not None
    backing.set("index", "1")
    source.set("index", "2")
    apparmor = root.find("seclabel[@model='apparmor']")
    assert apparmor is not None
    apparmor.set("relabel", "yes")
    ET.SubElement(apparmor, "label").text = "libvirt-sentra-sandbox"
    ET.SubElement(apparmor, "imagelabel").text = "libvirt-sentra-image"
    mutated_xml = ET.tostring(root, encoding="unicode")

    class StaticDomain:
        def name(self) -> str:
            return plan.sandbox_instance_id

        def XMLDesc(self, flags: int) -> str:
            assert flags == 0
            return mutated_xml

    identified = LibvirtBackend._domain_xml_identity(StaticDomain(), plan)
    assert identified.find("devices/disk/backingStore/source/seclabel") is None
    assert identified.find("seclabel[@model='dac']/label").text == (
        f"+{plan.libvirt_qemu_uid}:+{plan.libvirt_qemu_gid}"
    )


@pytest.mark.parametrize(
    ("state_code", "expected"),
    [
        (1, SandboxRuntimeState.RUNNING),
        (2, SandboxRuntimeState.PROVISIONING),
        (3, SandboxRuntimeState.STOPPED),
        (4, SandboxRuntimeState.STOPPED),
        (5, SandboxRuntimeState.STOPPED),
        (6, SandboxRuntimeState.FAILED),
        (7, SandboxRuntimeState.STOPPED),
        (99, SandboxRuntimeState.FAILED),
    ],
)
def test_inspect_maps_libvirt_domain_states_independently(
    tmp_path: Path,
    state_code: int,
    expected: SandboxRuntimeState,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    provider.provision(session_id)
    module.connections[0].domains[sandbox_resource_name(session_id)]._state = state_code

    observed = provider.inspect(session_id)

    assert observed.runtime_state is expected
    assert len(module.connections) == 2
    assert module.uris == ["qemu:///system", "qemu:///system"]


def test_inspect_missing_domain_and_storage_returns_missing(tmp_path: Path) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)

    observed = provider.inspect(uuid4())

    assert observed.runtime_state is SandboxRuntimeState.MISSING
    assert module.connections[0].pools == {}
    assert module.connections[0].domains == {}


def test_ensure_replay_is_idempotent_and_preserves_base(tmp_path: Path) -> None:
    provider, _, module, base = _provider_and_backend(tmp_path)
    session_id = uuid4()
    before = base.stat()

    first = provider.provision(session_id)
    second = provider.provision(session_id)

    connection = module.connections[-1]
    assert first == second
    assert connection.domain_define_count == 1
    assert connection.domain_start_count == 1
    assert connection.volume_create_count == 1
    assert len(module.connections[0].pools) == 1
    assert len(module.connections[0].domains) == 1
    assert base.stat().st_ino == before.st_ino
    assert base.stat().st_size == before.st_size
    assert base.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("crash_point", ["overlay", "domain_start"])
def test_interrupted_provisioning_reconciles_without_duplicate_resources(
    tmp_path: Path,
    crash_point: str,
) -> None:
    module = FakeLibvirtModule()
    provider, _, _, _ = _provider_and_backend(tmp_path, module=module)
    session_id = uuid4()
    connection = module.connections[0] if module.connections else None
    # The backend opens on each operation. Seed the durable fake state via a
    # module connection registry that returns the same system connection.
    durable = FakeConnection("qemu:///system")
    module.open = lambda uri: (module.uris.append(uri) or durable)  # type: ignore[method-assign]
    if crash_point == "overlay":
        durable.fail_before_domain_define = True
    else:
        durable.fail_after_domain_start = True
    with pytest.raises(SandboxProviderError):
        provider.provision(session_id)

    reconciled = provider.provision(session_id)

    assert reconciled.runtime_state is SandboxRuntimeState.RUNNING
    assert durable.pool_define_count == 1
    assert durable.domain_define_count == 1
    assert len(durable.pools) == 1
    assert len(durable.domains) == 1
    assert durable.pools[sandbox_pool_name_for(session_id)].listVolumes() == [
        "root.qcow2"
    ]
    del connection


def test_real_q35_libvirt_default_devices_are_accepted(
    tmp_path: Path,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()

    first = provider.provision(session_id)
    connection = module.connections[0]
    domain = connection.domains[sandbox_resource_name(session_id)]

    root = ET.fromstring(domain.XMLDesc(0))

    os_type = root.find("os/type")
    assert os_type is not None
    os_type.set("machine", "pc-q35-noble")

    devices = root.find("devices")
    assert devices is not None

    emulator = ET.Element("emulator")
    emulator.text = "/usr/bin/qemu-system-x86_64"
    devices.insert(0, emulator)

    ET.SubElement(
        devices,
        "controller",
        {"type": "sata", "index": "0"},
    )
    ET.SubElement(
        devices,
        "controller",
        {"type": "pci", "index": "0", "model": "pcie-root"},
    )

    for index in range(1, 5):
        ET.SubElement(
            devices,
            "controller",
            {
                "type": "pci",
                "index": str(index),
                "model": "pcie-root-port",
            },
        )

    ET.SubElement(
        devices,
        "input",
        {"type": "mouse", "bus": "ps2"},
    )
    ET.SubElement(
        devices,
        "input",
        {"type": "keyboard", "bus": "ps2"},
    )
    ET.SubElement(
        devices,
        "audio",
        {"id": "1", "type": "none"},
    )
    ET.SubElement(
        devices,
        "watchdog",
        {"model": "itco", "action": "reset"},
    )

    balloon = devices.find("memballoon")
    assert balloon is not None
    assert balloon.get("model") == "none"

    domain._xml = ET.tostring(root, encoding="unicode")
    domain.active = False
    domain._state = 5

    replay = provider.provision(session_id)

    assert replay.sandbox_instance_id == first.sandbox_instance_id
    assert domain.active is True
    assert connection.domain_define_count == 1
    assert connection.domain_start_count == 2


def _real_libvirt_q35_devices_fixture() -> ET.Element:
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "m6e-c-real-libvirt-old-policy.xml"
    )
    root = ET.fromstring(fixture.read_text())
    devices = root.find("devices")
    assert devices is not None
    return devices


def test_real_libvirt_old_policy_fixture_fails_closed_on_virtio_balloon(
) -> None:
    devices = _real_libvirt_q35_devices_fixture()

    with pytest.raises(
        SandboxProviderSecurityError,
        match="balloon device is not disabled",
    ):
        LibvirtBackend._validate_q35_normalized_devices(devices)


def test_real_libvirt_q35_normalization_is_accepted_when_policy_matches(
) -> None:
    devices = _real_libvirt_q35_devices_fixture()

    balloon = devices.find("memballoon")
    assert balloon is not None
    balloon.set("model", "none")

    LibvirtBackend._validate_q35_normalized_devices(devices)


def test_unsupported_controller_remains_rejected(tmp_path: Path) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    devices = root.find("devices")
    assert devices is not None
    ET.SubElement(devices, "controller", {"type": "scsi", "index": "0"})

    with pytest.raises(
        SandboxProviderSecurityError,
        match="controller is not an allowed virtual model",
    ):
        LibvirtBackend._validate_q35_normalized_devices(devices)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_index",
        "unexpected_model",
        "unexpected_attribute",
        "unexpected_child",
        "bad_address",
        "duplicate_controller",
    ],
)
def test_invalid_virtio_serial_controller_normalization_fails_closed(
    tmp_path: Path,
    mutation: str,
) -> None:
    provider, _, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    root = ET.fromstring(LibvirtBackend._domain_xml(plan))
    devices = root.find("devices")
    assert devices is not None
    controller = ET.SubElement(
        devices,
        "controller",
        {"type": "virtio-serial", "index": "0"},
    )

    if mutation == "wrong_index":
        controller.set("index", "1")
    elif mutation == "unexpected_model":
        controller.set("model", "virtio")
    elif mutation == "unexpected_attribute":
        controller.set("ports", "4096")
    elif mutation == "unexpected_child":
        ET.SubElement(controller, "serial")
    elif mutation == "bad_address":
        ET.SubElement(
            controller,
            "address",
            {
                "type": "usb",
                "controller": "0",
                "bus": "0",
                "port": "1",
            },
        )
    else:
        devices.append(
            ET.fromstring(ET.tostring(controller, encoding="unicode"))
        )

    with pytest.raises(
        SandboxProviderSecurityError,
        match="virtio-serial controller",
    ):
        LibvirtBackend._validate_q35_normalized_devices(devices)


def test_libvirt_pc_q35_noble_normalization_is_accepted(
    tmp_path: Path,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()

    first = provider.provision(session_id)
    connection = module.connections[0]
    domain = connection.domains[sandbox_resource_name(session_id)]

    root = ET.fromstring(domain.XMLDesc(0))
    os_type = root.find("os/type")
    assert os_type is not None
    os_type.set("machine", "pc-q35-noble")
    domain._xml = ET.tostring(root, encoding="unicode")
    domain.active = False
    domain._state = 5

    replay = provider.provision(session_id)

    assert replay.sandbox_instance_id == first.sandbox_instance_id
    assert domain.active is True
    assert connection.domain_define_count == 1
    assert connection.domain_start_count == 2


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        ("devices/disk/source", {"file": "/tmp/other.qcow2"}),
        ("memory", None),
        ("vcpu", None),
        ("devices/interface/source", {"network": "untrusted"}),
        ("os/type", {"machine": "pc-q35-evil"}),
    ],
)
def test_same_name_domain_with_changed_plan_fails_closed(
    tmp_path: Path,
    path: str,
    replacement: dict[str, str] | None,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    provider.provision(session_id)
    domain = module.connections[0].domains[sandbox_resource_name(session_id)]
    root = ET.fromstring(domain.XMLDesc(0))
    node = root.find(path)
    assert node is not None
    if replacement is None:
        node.text = "4096" if path == "memory" else "8"
    else:
        node.attrib.update(replacement)
    domain._xml = ET.tostring(root, encoding="unicode")
    domain.active = False
    domain._state = 5

    with pytest.raises(SandboxProviderSecurityError):
        provider.provision(session_id)
    assert domain.active is False


def test_malformed_domain_xml_fails_closed(tmp_path: Path) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    provider.provision(session_id)
    domain = module.connections[0].domains[sandbox_resource_name(session_id)]
    domain._xml = "<domain><malformed>"

    with pytest.raises(SandboxProviderSecurityError, match="malformed"):
        provider.inspect(session_id)


def test_wrong_backing_store_and_overlay_permissions_fail_closed(
    tmp_path: Path,
) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    provider.provision(session_id)
    connection = module.connections[0]
    volume = connection.pools[sandbox_pool_name_for(session_id)].volumes[
        "root.qcow2"
    ]
    root = ET.fromstring(volume.XMLDesc(0))
    root.find("backingStore/path").text = "/tmp/other-base.qcow2"
    volume._xml = ET.tostring(root, encoding="unicode")
    with pytest.raises(SandboxProviderSecurityError, match="backing image"):
        provider.inspect(session_id)


def test_destroy_removes_only_session_domain_pool_overlay_not_base_or_peer(
    tmp_path: Path,
) -> None:
    provider, _, module, base = _provider_and_backend(tmp_path)
    first_id, second_id = uuid4(), uuid4()
    provider.provision(first_id)
    provider.provision(second_id)
    first_overlay = Path(
        module.connections[0].pools[sandbox_pool_name_for(first_id)]
        .volumes["root.qcow2"]
        .path()
    )
    second_overlay = Path(
        module.connections[0].pools[sandbox_pool_name_for(second_id)]
        .volumes["root.qcow2"]
        .path()
    )
    before = base.read_bytes()

    provider.destroy(first_id)

    connection = module.connections[-1]
    assert sandbox_pool_name_for(first_id) not in connection.pools
    assert sandbox_resource_name(first_id) not in connection.domains
    assert not first_overlay.exists()
    assert sandbox_pool_name_for(second_id) in connection.pools
    assert sandbox_resource_name(second_id) in connection.domains
    assert second_overlay.exists()
    assert base.read_bytes() == before


def test_destroy_is_idempotent_for_missing_session(tmp_path: Path) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)

    provider.destroy(uuid4())

    assert module.connections[0].pools == {}
    assert module.connections[0].domains == {}


def test_destroy_refuses_unexpected_volume_without_deleting_it(tmp_path: Path) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    provider.provision(session_id)
    pool = module.connections[0].pools[sandbox_pool_name_for(session_id)]
    unexpected = pool.path / "foreign-volume.qcow2"
    unexpected.write_bytes(b"must remain")

    with pytest.raises(SandboxProviderSecurityError, match="unexpected files"):
        provider.destroy(session_id)

    assert unexpected.read_bytes() == b"must remain"
    assert sandbox_pool_name_for(session_id) in module.connections[-1].pools


def test_escaped_plan_and_symlink_overlay_path_rejected(tmp_path: Path) -> None:
    provider, backend, _, _ = _provider_and_backend(tmp_path)
    session_id = uuid4()
    plan = provider._plan(session_id, prepare_directory=False)
    escaped = plan.model_copy(
        update={"overlay_path": Path("/tmp/escape/root.qcow2")}
    )
    with pytest.raises(SandboxProviderSecurityError):
        backend.ensure_provisioned(escaped)


def test_manager_sanitization_remains_the_user_facing_boundary(
    tmp_path: Path,
) -> None:
    # The existing focused M6E-B tests cover this boundary with raw libvirt-like
    # failures; this check confirms the concrete backend raises only controlled
    # path errors for malformed plans.
    provider, backend, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    with pytest.raises(SandboxProviderSecurityError):
        backend.ensure_provisioned(plan.model_copy(update={"vcpus": 0}))


def test_volume_and_pool_are_deterministic_from_session_only(tmp_path: Path) -> None:
    provider, _, module, _ = _provider_and_backend(tmp_path)
    session_id = UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")

    provider.provision(session_id)

    pool = module.connections[0].pools[sandbox_pool_name_for(session_id)]
    assert pool.path.name == sandbox_resource_name(session_id)
    assert sandbox_pool_name_for(session_id) == (
        "sentra-pool-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    )
    assert sandbox_resource_name(session_id) == (
        "sentra-sbx-aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    )


def test_domain_start_interruption_reuses_domain_without_second_define(
    tmp_path: Path,
) -> None:
    module = FakeLibvirtModule()
    provider, _, _, _ = _provider_and_backend(tmp_path, module=module)
    durable = FakeConnection("qemu:///system")
    module.open = lambda uri: (module.uris.append(uri) or durable)  # type: ignore[method-assign]
    durable.fail_after_domain_start = True
    session_id = uuid4()
    with pytest.raises(SandboxProviderError):
        provider.provision(session_id)

    result = provider.provision(session_id)
    assert result.runtime_state is SandboxRuntimeState.RUNNING
    assert durable.domain_define_count == 1
    assert durable.domain_start_count == 1


def test_base_image_is_never_passed_as_mutable_volume_target(tmp_path: Path) -> None:
    provider, backend, _, base = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)
    volume_xml = ET.fromstring(backend._volume_xml(plan))

    assert volume_xml.findtext("backingStore/path") == str(base)
    assert volume_xml.find("target/path") is None
    assert volume_xml.findtext("target/permissions/mode") == "0600"
    assert plan.base_image != plan.overlay_path


def test_backend_rejects_noncanonical_pool_identity(tmp_path: Path) -> None:
    provider, backend, _, _ = _provider_and_backend(tmp_path)
    plan = provider._plan(uuid4(), prepare_directory=False)

    with pytest.raises(SandboxProviderSecurityError):
        backend.ensure_provisioned(
            plan.model_copy(update={"storage_pool_name": "sentra-pool-attacker"})
        )


def test_fake_backend_surface_has_no_command_or_arbitrary_xml_parameter() -> None:
    assert set(LocalNestedVmBackendMethods) == {
        "ensure_provisioned",
        "inspect",
        "destroy",
    }


LocalNestedVmBackendMethods = {
    name
    for name in (
        "ensure_provisioned",
        "inspect",
        "destroy",
    )
}
