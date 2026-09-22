"""Hand-authored Milestone 5 control adapters."""

from .base import AdapterContext, ControlAdapter
from .passwd_permissions import PasswdPermissionsAdapter
from .ssh_root_login import SshRootLoginAdapter
from .ufw_service import UfwServiceAdapter


def adapter_registry() -> dict[str, ControlAdapter]:
    """Return fresh, stateless adapter instances in stable control order."""

    adapters: tuple[ControlAdapter, ...] = (
        PasswdPermissionsAdapter(),
        SshRootLoginAdapter(),
        UfwServiceAdapter(),
    )
    return {adapter.control_id: adapter for adapter in adapters}


__all__ = [
    "AdapterContext",
    "ControlAdapter",
    "PasswdPermissionsAdapter",
    "SshRootLoginAdapter",
    "UfwServiceAdapter",
    "adapter_registry",
]
