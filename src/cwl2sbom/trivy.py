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

"""Invoke Trivy without a shell and retain its original CycloneDX output."""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from transpiler_mate.api import PluginFailureError


class Trivy:
    def __init__(self, executable: str, cache: Path | None, timeout: int) -> None:
        self.executable = executable
        self.cache = cache
        self.timeout = timeout

    def run(self, args: list[str]) -> str:
        try:
            result = subprocess.run(  # nosec B603
                [self.executable, *args],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError as exc:
            raise PluginFailureError(
                "Trivy executable not found; install Trivy or set --trivy"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise PluginFailureError(
                f"Trivy exceeded the {self.timeout}s timeout"
            ) from exc
        if result.returncode:
            # Registry diagnostics can contain authentication information; do not echo them.
            raise PluginFailureError(
                f"Trivy failed with exit code {result.returncode}; check registry access and Trivy configuration"
            )
        return result.stdout

    def version(self) -> str:
        data = json.loads(self.run(["version", "--format", "json"]))
        version = data.get("Version")
        if not isinstance(version, str) or not version:
            raise PluginFailureError("Trivy did not report its version")
        return version

    def generate(self, image: str, platform: str, output: Path) -> dict[str, Any]:
        args = [
            "image",
            "--image-src",
            "remote",
            "--platform",
            platform,
            "--format",
            "cyclonedx",
            "--output",
            str(output),
            "--quiet",
            "--timeout",
            f"{self.timeout}s",
        ]
        if self.cache is not None:
            args.extend(["--cache-dir", str(self.cache)])
        self.run([*args, "--", image])
        data = json.loads(output.read_text(encoding="utf-8"))
        if data.get("bomFormat") != "CycloneDX" or not data.get("specVersion"):
            raise PluginFailureError("Trivy did not produce a CycloneDX SBOM")
        component = data.get("metadata", {}).get("component", {})
        props = component.get("properties", [])
        digests = sorted(
            {
                p["value"]
                for p in props
                if p.get("name") == "aquasecurity:trivy:RepoDigest"
                and re.fullmatch(r"[^\s]+@sha256:[a-f0-9]{64}", str(p.get("value", "")))
            }
        )
        if not digests:
            raise PluginFailureError(f"Trivy SBOM has no repository digest for {image}")
        image_ids = [
            p["value"] for p in props if p.get("name") == "aquasecurity:trivy:ImageID"
        ]
        return {
            "repository_digests": digests,
            "image_ids": image_ids,
            "sbom_spec_version": data["specVersion"],
        }
