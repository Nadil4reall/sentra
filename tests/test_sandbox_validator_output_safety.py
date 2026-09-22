"""Focused M5 report-destination safety regression tests.

These tests use only temporary paths and tripwires.  They never inspect or
modify the developer host's system configuration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.sandbox_validator import cli


@pytest.fixture
def report_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    directory = tmp_path / "project" / "data" / "sandbox"
    directory.mkdir(parents=True)
    monkeypatch.setattr(cli, "REPORT_OUTPUT_DIRECTORY", directory)
    return directory


def _install_pre_validation_tripwires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unsafe output crossed into validation")

    monkeypatch.setattr(cli, "load_validation_inputs", fail)
    monkeypatch.setattr(cli, "AdapterContext", fail)
    monkeypatch.setattr(cli, "SandboxValidator", fail)


@pytest.mark.parametrize(
    "unsafe_output",
    [
        Path("/etc/passwd"),
        Path("/etc/shadow"),
        Path("/etc/ssh/sshd_config"),
    ],
)
def test_cli_rejects_absolute_system_output_before_validation(
    report_directory: Path,
    unsafe_output: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_pre_validation_tripwires(monkeypatch)

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(unsafe_output),
                "--overwrite",
            ]
        )

    assert raised.value.code == 2
    assert "must be beneath" in capsys.readouterr().err


def test_cli_rejects_parent_traversal_before_validation(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_pre_validation_tripwires(monkeypatch)
    traversal = report_directory / ".." / ".." / "etc" / "passwd"

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(traversal),
            ]
        )

    assert raised.value.code == 2
    assert "parent-directory traversal" in capsys.readouterr().err


def test_cli_rejects_symlink_to_system_file_before_validation(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_pre_validation_tripwires(monkeypatch)
    output = report_directory / "unsafe-link.yaml"
    output.symlink_to("/etc/passwd")

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(output),
                "--overwrite",
            ]
        )

    assert raised.value.code == 2
    assert "must not be a symlink" in capsys.readouterr().err
    assert output.is_symlink()


def test_cli_rejects_symlink_parent_and_nonregular_target_before_validation(
    report_directory: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_pre_validation_tripwires(monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = report_directory / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--control",
                "7.1.1",
                "--plan",
                "--output",
                str(linked_parent / "report.yaml"),
            ]
        )
    assert "symlink directory" in capsys.readouterr().err

    directory_target = report_directory / "directory.yaml"
    directory_target.mkdir()
    with pytest.raises(SystemExit):
        cli.main(
            [
                "--control",
                "7.1.1",
                "--plan",
                "--output",
                str(directory_target),
                "--overwrite",
            ]
        )
    assert "regular file" in capsys.readouterr().err


def test_cli_overwrite_rejects_non_m5_file_before_validation(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_pre_validation_tripwires(monkeypatch)
    output = report_directory / "operator-file.yaml"
    original = b"not: an M5 validation report\n"
    output.write_bytes(original)

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--plan",
                "--output",
                str(output),
                "--overwrite",
            ]
        )

    assert raised.value.code == 2
    assert "not a valid existing M5 report" in capsys.readouterr().err
    assert output.read_bytes() == original


def test_output_preparation_failure_happens_before_validation_and_cleans_reservation(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = {"load": 0, "validate": 0}

    def fail_load(*_args: object, **_kwargs: object) -> None:
        calls["load"] += 1
        raise AssertionError("input loading occurred after preparation failure")

    def fail_pending(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("synthetic unwritable report directory")

    monkeypatch.setattr(cli, "load_validation_inputs", fail_load)
    monkeypatch.setattr(cli, "_create_pending_file", fail_pending)
    output = report_directory / "unwritable.yaml"

    with pytest.raises(SystemExit) as raised:
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(output),
            ]
        )

    assert raised.value.code == 2
    assert "synthetic unwritable" in capsys.readouterr().err
    assert calls == {"load": 0, "validate": 0}
    assert not output.exists()
    assert list(report_directory.iterdir()) == []


def test_input_failure_before_validator_cleans_incomplete_reservation(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_load(*_args: object, **_kwargs: object) -> None:
        raise ValueError("synthetic invalid input")

    monkeypatch.setattr(cli, "load_validation_inputs", fail_load)
    output = report_directory / "invalid-input.yaml"

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(output),
            ]
        )

    assert not output.exists()
    assert list(report_directory.iterdir()) == []


def test_execute_failure_after_validator_starts_preserves_clear_incomplete_marker(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"validate": 0}

    class FailingValidator:
        def __init__(self, *, context: object) -> None:
            self.context = context

        def validate(self, *_args: object, **_kwargs: object) -> None:
            calls["validate"] += 1
            raise OSError("synthetic post-mutation failure")

    monkeypatch.setattr(cli, "load_validation_inputs", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "AdapterContext", lambda **_kwargs: object())
    monkeypatch.setattr(cli, "SandboxValidator", FailingValidator)
    output = report_directory / "incomplete.yaml"

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(output),
            ]
        )

    assert calls["validate"] == 1
    content = output.read_text(encoding="utf-8")
    assert "NOT A COMPLETED VALIDATION REPORT" in content
    assert "complete: false" in content
    assert not list(report_directory.glob(".*.pending"))


def test_execute_final_publication_failure_preserves_clear_incomplete_marker(
    report_directory: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SuccessfulValidator:
        def __init__(self, *, context: object) -> None:
            self.context = context

        def validate(self, *_args: object, **_kwargs: object) -> object:
            return object()

    def fail_publication(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic final publication failure")

    monkeypatch.setattr(cli, "load_validation_inputs", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(cli, "AdapterContext", lambda **_kwargs: object())
    monkeypatch.setattr(cli, "SandboxValidator", SuccessfulValidator)
    monkeypatch.setattr(cli, "report_to_yaml", lambda _report: "complete: true\n")
    monkeypatch.setattr(cli, "_write_private_report", fail_publication)
    output = report_directory / "publication-failed.yaml"

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--control",
                "7.1.1",
                "--execute",
                "--output",
                str(output),
            ]
        )

    content = output.read_text(encoding="utf-8")
    assert "NOT A COMPLETED VALIDATION REPORT" in content
    assert "complete: false" in content
    assert not list(report_directory.glob(".*.pending"))
