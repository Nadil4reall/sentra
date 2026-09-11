"""Deterministic, human-readable YAML serialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from .models import Catalog, ControlDocument


class LiteralSafeDumper(yaml.SafeDumper):
    """Safe dumper that renders multiline source fields with literal blocks."""


def _represent_string(dumper: yaml.Dumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


LiteralSafeDumper.add_representer(str, _represent_string)


def serialize_yaml(value: BaseModel | dict[str, Any]) -> str:
    data = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return yaml.dump(
        data,
        Dumper=LiteralSafeDumper,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=100,
    )


def _write_yaml(path: Path, value: BaseModel | dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(serialize_yaml(value), encoding="utf-8")
    temporary.replace(path)
    return path


def control_filename(control_id: str) -> str:
    return control_id.replace(".", "_") + ".yaml"


def write_control(output_directory: str | Path, document: ControlDocument) -> Path:
    destination = Path(output_directory) / "controls" / control_filename(document.control.id)
    return _write_yaml(destination, document)


def write_catalog(output_directory: str | Path, catalog: Catalog) -> Path:
    return _write_yaml(Path(output_directory) / "catalog.yaml", catalog)

