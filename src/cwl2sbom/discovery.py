# Copyright 2026 Terradue
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

"""Discover effective Docker requirements along reachable workflow paths."""

from __future__ import annotations

import re
from typing import Any

from transpiler_mate.api import PluginFailureError


def docker(node: dict[str, Any], field: str) -> dict[str, Any] | None:
    entries = node.get(field, []) or []
    if isinstance(entries, dict):
        value = entries.get("DockerRequirement")
        return dict(value or {}) if "DockerRequirement" in entries else None
    matches = [
        r for r in entries if str(r.get("class", "")).rsplit("#", 1)[-1] == "DockerRequirement"
    ]
    if len(matches) > 1:
        raise PluginFailureError("Duplicate DockerRequirement declaration")
    return dict(matches[0]) if matches else None


def image_reference(
    requirement: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    if requirement is None:
        return None, "No DockerRequirement"
    image = requirement.get("dockerPull")
    if not isinstance(image, str) or not image:
        return (
            None,
            "DockerRequirement has no dockerPull; image builds and local dockerImageId are unsupported",
        )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]*", image):
        return None, "dockerPull is not a literal container reference"
    return image, None


def discover(root: dict[str, Any], processes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return one coverage entry per reachable tool invocation, with inheritance."""
    records: list[dict[str, Any]] = []

    def visit(
        node: dict[str, Any],
        path: str,
        required: dict[str, Any] | None,
        hinted: dict[str, Any] | None,
        ancestors: frozenset[str],
    ) -> None:
        identity = str(node.get("id", path))
        if identity in ancestors:
            raise PluginFailureError(f"Recursive workflow reference: {identity}")
        own_req, own_hint = docker(node, "requirements"), docker(node, "hints")
        required = own_req if own_req is not None else required
        hinted = own_hint if own_hint is not None else hinted
        if node.get("class") == "Workflow":
            for step in node.get("steps", []):
                run = step["run"]
                child = (
                    run
                    if isinstance(run, dict)
                    else (processes.get(run) or processes.get(run.removeprefix("#")))
                )
                if child is None:
                    raise PluginFailureError(f"Unresolved workflow step: {run}")
                step_req, step_hint = (
                    docker(step, "requirements"),
                    docker(step, "hints"),
                )
                visit(
                    child,
                    f"{path}/{step['id']}",
                    step_req if step_req is not None else required,
                    step_hint if step_hint is not None else hinted,
                    ancestors | {identity},
                )
            return
        if node.get("class") == "ExpressionTool":
            records.append(
                {
                    "step": path,
                    "process": identity,
                    "status": "not-applicable",
                    "reason": "ExpressionTool runs in the CWL engine",
                }
            )
            return
        image, reason = image_reference(required if required is not None else hinted)
        records.append(
            {
                "step": path,
                "process": identity,
                "image": image,
                "status": "declared" if image else "uncovered",
                "reason": reason,
                "declaration": "requirement" if required is not None else "hint",
            }
        )

    visit(root, str(root["id"]), None, None, frozenset())
    return records
