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

"""Generate a local SBOM bundle for a selected CWL process."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cwl_utils.parser import save
from pydantic import BaseModel, ConfigDict, Field
from transpiler_mate.api import (
    PluginError,
    PluginExecutionError,
    PluginFailureError,
    transpiler_plugin,
)

from .__about__ import __version__
from .discovery import discover
from .trivy import Trivy

if TYPE_CHECKING:
    from transpiler_mate.api import TranspilerContext


class CWL2SBOMOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output: Path = Field(
        default=Path("sbom"), description="New output directory (must not exist)"
    )
    platform: str = Field(
        pattern=r"^[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9_.-]+)?$",
        description="Explicit OCI platform, e.g. linux/amd64",
    )
    trivy: str = Field(
        default="trivy", min_length=1, description="Installed Trivy executable"
    )
    cache_dir: Path | None = Field(default=None, description="Trivy cache directory")
    timeout: int = Field(
        default=600, gt=0, description="Timeout in seconds per Trivy invocation"
    )
    allow_incomplete: bool = Field(
        default=False,
        description="Allow tools without inspectable dockerPull references",
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def inventory(
    context: TranspilerContext,
    records: list[dict[str, Any]],
    images: list[dict[str, Any]],
) -> dict[str, Any]:
    root = "workflow"
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    image_refs = {image["reference"]: image["bom_ref"] for image in images}
    tool_refs = []
    for index, record in enumerate(records):
        ref = f"tool-{index}"
        tool_refs.append(ref)
        components.append(
            {
                "type": "application",
                "bom-ref": ref,
                "name": record["process"],
                "properties": [
                    {"name": "transpiler-mate:step", "value": record["step"]},
                    {"name": "transpiler-mate:coverage", "value": record["status"]},
                ],
            }
        )
        dependencies.append(
            {
                "ref": ref,
                "dependsOn": [image_refs[record["image"]]]
                if record.get("image")
                else [],
            }
        )
    for image in images:
        components.append(
            {
                "type": "container",
                "bom-ref": image["bom_ref"],
                "name": image["reference"],
                "version": image["repository_digests"][0].split("@", 1)[1],
                "properties": [
                    {"name": "transpiler-mate:platform", "value": image["platform"]}
                ],
                "externalReferences": [
                    {
                        "type": "bom",
                        "url": image["sbom"],
                        "hashes": [{"alg": "SHA-256", "content": image["sbom_sha256"]}],
                    }
                ],
            }
        )
    dependencies.insert(0, {"ref": root, "dependsOn": tool_refs})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root,
                "name": context.metadata.name,
                "version": context.metadata.software_version,
            },
            "tools": [
                {
                    "vendor": "Transpiler-Mate",
                    "name": "cwl2sbom",
                    "version": __version__,
                }
            ],
        },
        "components": components,
        "dependencies": dependencies,
        "compositions": [{"aggregate": "incomplete", "assemblies": [root]}],
    }


def generate(
    context: TranspilerContext, options: CWL2SBOMOptions, records: list[dict[str, Any]]
) -> None:
    scanner = Trivy(options.trivy, options.cache_dir, options.timeout)
    references = sorted({r["image"] for r in records if r.get("image")})
    version = scanner.version() if references else None
    images = []
    (options.output / "images").mkdir()
    for reference in references:
        # Reference hash avoids unsafe filenames and collisions between registry aliases.
        key = hashlib.sha256((reference + "\n" + options.platform).encode()).hexdigest()
        relative = f"images/{key}.cdx.json"
        path = options.output / relative
        details = scanner.generate(reference, options.platform, path)
        images.append(
            {
                "reference": reference,
                "platform": options.platform,
                **details,
                "sbom": relative,
                "sbom_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bom_ref": f"image-{key}",
                "steps": [r["step"] for r in records if r.get("image") == reference],
            }
        )
    write_json(
        options.output / "images.lock.json",
        {
            "schema_version": 1,
            "source": str(context.source),
            "entrypoint": context.process_id,
            "platform": options.platform,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "trivy_version": version,
            "plugin_version": __version__,
            "images": images,
        },
    )
    write_json(
        options.output / "coverage.json",
        {
            "schema_version": 1,
            "complete": all(r["status"] != "uncovered" for r in records),
            "scope": "Declared containers in reachable tools; runtime downloads and host software are not inspected",
            "tools": records,
        },
    )
    write_json(
        options.output / "workflow.cdx.json", inventory(context, records, images)
    )


@transpiler_plugin(
    name="cwl2sbom",
    description="Generate local container SBOMs with Trivy; publication stays with ORAS.",
    options_model=CWL2SBOMOptions,
)
def cwl2sbom(context: TranspilerContext, options: CWL2SBOMOptions) -> None:
    created = False
    try:
        root = save(context.resolved_process, relative_uris=False)
        processes = {
            p["id"]: p
            for p in save(list(context.processes), relative_uris=False)["$graph"]
        }
        records = discover(root, processes)
        gaps = [r for r in records if r["status"] == "uncovered"]
        if gaps and not options.allow_incomplete:
            raise PluginFailureError(
                "Container coverage incomplete: "
                + "; ".join(f"{r['step']}: {r['reason']}" for r in gaps)
                + ". Use --allow-incomplete to export the gaps."
            )
        options.output.mkdir(parents=True, exist_ok=False)
        created = True
        generate(context, options, records)
    except Exception as exc:
        if created:
            shutil.rmtree(options.output)
        if isinstance(exc, PluginError):
            raise
        raise PluginExecutionError(f"Unable to generate SBOM bundle: {exc}") from exc
