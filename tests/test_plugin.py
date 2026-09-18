# Copyright 2026 Transpiler-Mate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from transpiler_mate.api import PluginError
from transpiler_mate.runtime.cli import main
from transpiler_mate.runtime.context_resolver import DefaultTranspilerContextResolver

from cwl2sbom.discovery import discover
from cwl2sbom.plugin import CWL2SBOMOptions, cwl2sbom
from cwl2sbom.trivy import Trivy

DIGEST = "a" * 64


def tool(identity: str = "tool", **kwargs: Any) -> dict[str, Any]:
    return {"class": "CommandLineTool", "id": identity, **kwargs}


def req(image: str) -> list[dict[str, str]]:
    return [{"class": "DockerRequirement", "dockerPull": image}]


def test_nested_inheritance_and_reused_tool() -> None:
    shared = tool()
    child = {
        "class": "Workflow",
        "id": "child",
        "steps": [{"id": "leaf", "run": "tool"}],
    }
    root = {
        "class": "Workflow",
        "id": "main",
        "requirements": req("base:1"),
        "steps": [
            {"id": "a", "run": "#child"},
            {"id": "b", "run": "tool", "requirements": req("other:2")},
        ],
    }
    records = discover(root, {"tool": shared, "child": child, "unused": tool("unused")})
    assert [r["image"] for r in records] == ["base:1", "other:2"]
    assert len(records) == 2


def test_requirement_beats_hint_and_child_overrides() -> None:
    root = {
        "class": "Workflow",
        "id": "main",
        "requirements": req("base"),
        "steps": [
            {"id": "a", "run": tool(hints=req("ignored"))},
            {"id": "b", "run": tool(requirements=req("override"))},
        ],
    }
    assert [r["image"] for r in discover(root, {})] == ["base", "override"]


@pytest.mark.parametrize(
    "requirement",
    [
        [],
        [{"class": "DockerRequirement", "dockerFile": "FROM alpine"}],
        req("$(inputs.image)"),
        req("--bad"),
        req("a; touch /tmp/oops"),
    ],
)
def test_coverage_gaps(requirement: list[dict[str, str]]) -> None:
    record = discover(tool(requirements=requirement), {})[0]
    assert record["status"] == "uncovered"


def test_expression_tool() -> None:
    assert (
        discover({"id": "expr", "class": "ExpressionTool"}, {})[0]["status"]
        == "not-applicable"
    )


def test_cycle_and_missing_run() -> None:
    root = {"class": "Workflow", "id": "main", "steps": [{"id": "a", "run": "main"}]}
    with pytest.raises(PluginError, match="Recursive"):
        discover(root, {"main": root})
    with pytest.raises(PluginError, match="Unresolved"):
        discover(root, {})


@pytest.fixture
def source(tmp_path: Path) -> Path:
    text = (Path(__file__).parent / "fixtures/hello.cwl").read_text()
    path = tmp_path / "hello.cwl"
    path.write_text(
        text
        + "\nrequirements:\n  DockerRequirement:\n    dockerPull: example.org/tool:1\n"
    )
    return path


@pytest.fixture
def scanner(monkeypatch: pytest.MonkeyPatch) -> Mock:
    def run(self: Trivy, args: list[str]) -> str:
        if args[0] == "version":
            return '{"Version":"test-1"}'
        output = Path(args[args.index("--output") + 1])
        output.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "container",
                            "name": "example.org/tool",
                            "properties": [
                                {
                                    "name": "aquasecurity:trivy:RepoDigest",
                                    "value": f"example.org/tool@sha256:{DIGEST}",
                                },
                                {
                                    "name": "aquasecurity:trivy:ImageID",
                                    "value": f"sha256:{DIGEST}",
                                },
                            ],
                        }
                    },
                    "components": [],
                }
            )
        )
        return ""

    mock = Mock(side_effect=run)
    monkeypatch.setattr(Trivy, "run", lambda self, args: mock(self, args))
    return mock


def test_cli_bundle(source: Path, scanner: Mock, tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    result = CliRunner().invoke(
        main,
        [
            "cwl2sbom",
            "--platform",
            "linux/amd64",
            "--output",
            str(output),
            f"{source}#hello",
        ],
    )
    assert result.exit_code == 0, result.output
    lock = json.loads((output / "images.lock.json").read_text())
    assert lock["trivy_version"] == "test-1"
    image = lock["images"][0]
    assert image["repository_digests"] == [f"example.org/tool@sha256:{DIGEST}"]
    assert (output / image["sbom"]).is_file()
    assert json.loads((output / "coverage.json").read_text())["complete"]
    bom = json.loads((output / "workflow.cdx.json").read_text())
    assert bom["dependencies"][1]["dependsOn"] == [image["bom_ref"]]
    args = scanner.call_args_list[-1].args[1]
    assert args[args.index("--image-src") + 1] == "remote"
    assert args[-2:] == ["--", "example.org/tool:1"]


def test_existing_output_preserved(source: Path, tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    output.mkdir()
    (output / "keep").write_text("keep")
    context = DefaultTranspilerContextResolver().resolve(f"{source}#hello")
    with pytest.raises(PluginError):
        cwl2sbom.execute(
            context, CWL2SBOMOptions(platform="linux/amd64", output=output)
        )
    assert (output / "keep").read_text() == "keep"


def test_missing_binary_cleans_output(source: Path, tmp_path: Path) -> None:
    context = DefaultTranspilerContextResolver().resolve(f"{source}#hello")
    output = tmp_path / "bundle"
    with pytest.raises(PluginError, match="executable not found"):
        cwl2sbom.execute(
            context,
            CWL2SBOMOptions(
                platform="linux/amd64", output=output, trivy="/nonexistent/trivy"
            ),
        )
    assert not output.exists()


def test_incomplete_export_without_trivy(tmp_path: Path) -> None:
    context = DefaultTranspilerContextResolver().resolve(
        f"{Path(__file__).parent / 'fixtures/hello.cwl'}#hello"
    )
    output = tmp_path / "bundle"
    with pytest.raises(PluginError, match="coverage incomplete"):
        cwl2sbom.execute(
            context, CWL2SBOMOptions(platform="linux/amd64", output=output)
        )
    assert not output.exists()
    cwl2sbom.execute(
        context,
        CWL2SBOMOptions(platform="linux/amd64", output=output, allow_incomplete=True),
    )
    assert not json.loads((output / "coverage.json").read_text())["complete"]


def test_bad_sbom_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5"}')
    monkeypatch.setattr(Trivy, "run", lambda *args: "")
    with pytest.raises(PluginError, match="no repository digest"):
        Trivy("trivy", None, 60).generate("example:1", "linux/amd64", path)


def test_required_platform(source: Path) -> None:
    result = CliRunner().invoke(main, ["cwl2sbom", f"{source}#hello"])
    assert result.exit_code != 0
    assert "platform" in result.output


def test_scan_failure_rolls_back(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = DefaultTranspilerContextResolver().resolve(f"{source}#hello")
    monkeypatch.setattr(Trivy, "version", lambda self: "test")

    def fail(self: Trivy, image: str, platform: str, output: Path) -> dict[str, Any]:
        output.write_text("partial")
        raise PluginError("scanner failed")

    monkeypatch.setattr(Trivy, "generate", fail)
    output = tmp_path / "bundle"
    with pytest.raises(PluginError, match="scanner failed"):
        cwl2sbom.execute(
            context, CWL2SBOMOptions(platform="linux/amd64", output=output)
        )
    assert not output.exists()


def test_timeout_and_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    run = Mock(side_effect=subprocess.TimeoutExpired("trivy", 1))
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(PluginError, match="timeout"):
        Trivy("trivy", None, 1).version()
    run.side_effect = None
    run.return_value = subprocess.CompletedProcess([], 1, "", "sensitive token")
    with pytest.raises(PluginError, match="exit code 1") as error:
        Trivy("trivy", None, 1).version()
    assert "sensitive" not in str(error.value)
