# CWL 2 SBOM

[![PyPI - Version](https://img.shields.io/pypi/v/cwl2sbom.svg)](https://pypi.org/project/cwl2sbom)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/cwl2sbom.svg)](https://pypi.org/project/cwl2sbom)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/transpiler-mate/cwl2sbom/package.yaml?branch=develop&event=push&label=build&logo=githubactions)](https://github.com/transpiler-mate/cwl2sbom/actions/workflows/package.yaml?query=branch%3Adevelop)
[![Code coverage](https://img.shields.io/codecov/c/github/transpiler-mate/cwl2sbom/develop?logo=codecov)](https://app.codecov.io/gh/transpiler-mate/cwl2sbom/tree/develop)

Generate local CycloneDX SBOMs for the containers declared by a CWL workflow using Trivy. Bootstrapped from the [Transpiler-Mate plugin project template](https://github.com/transpiler-mate/transpiler-mate-plugin-project-template).

## Install

Python 3.10+ and an installed [Trivy](https://trivy.dev/docs/latest/getting-started/installation/) executable are required. From this checkout:

```sh
pip install transpiler-mate-runtime .
```

## Generate

```sh
transpiler-mate cwl2sbom --platform linux/amd64 --output sbom \
  workflow.cwl#main
```

For the workspace example:

```sh
transpiler-mate cwl2sbom --platform linux/amd64 \
  --output tmp/build/burned-area-severity/sbom \
  tmp/burned-area-severity.cwl#burned-area-severity
```

An explicit CWL entrypoint and platform are required. Trivy downloads and inspects images directly from their registries; no Docker daemon or container execution is involved. Registry authentication uses Trivy's normal configuration. Install Trivy separately; the plugin does not download executables.

| Output | Contents |
| --- | --- |
| `workflow.cdx.json` | CycloneDX 1.5 workflow → tool invocation → container inventory |
| `images/*.cdx.json` | Original Trivy SBOM for each distinct image reference and platform |
| `images.lock.json` | Original references, reported repository digests and image IDs, platform, step associations, checksums, and generator versions |
| `coverage.json` | Covered declarations, uncovered tools, and expression tools |

Image filenames hash the original reference and platform, avoiding registry aliases and unsafe filename characters. Repeated references are inspected once per invocation. Different aliases may be inspected separately, even if they ultimately resolve to the same image. Trivy's cache handles reuse of downloaded/analyzed content.

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--platform` | required | OCI platform, such as `linux/amd64` or `linux/arm64/v8` |
| `--output` | `sbom` | New directory; existing directories are rejected |
| `--trivy` | `trivy` | Installed executable name or path |
| `--cache-dir` | Trivy default | Persistent Trivy cache directory |
| `--timeout` | `600` | Seconds per Trivy invocation |
| `--allow-incomplete` | false | Export known containers and report uncovered tools |

The plugin follows nested workflows and effective Docker requirements/hints. It reports missing containers, nonliteral references, and build-only Docker requirements. ExpressionTools are marked not applicable because they run in the CWL engine. No image builds are performed. Failure removes the newly created bundle; existing outputs are preserved.

## Publish and scan separately

Publish or attach the generated files using your existing ORAS pipeline. This plugin does not push, retrieve OCI referrers, sign artifacts, or attach SBOMs. The lock file connects each image SBOM to its container identity even when the bundle is attached to a workflow artifact.

See the [offline Trivy scanning guide](docs/how-to/offline-scanning.md) for database preparation and transfer, per-image vulnerability reports, separate license assessment, and CI exit-code handling. Scanning and policy enforcement run downstream of this plugin.

## Scope and reproducibility

A tag is resolved by Trivy during inspection. The lock records the repository digest(s) and image configuration ID reported by that inspection, together with the requested platform. It does not pre-resolve tags or rewrite CWL. A reported repository digest can identify a multi-platform index: it must not be mistaken for a selected child manifest digest. For subsequent reproducible invocations, use digest-pinned references and the same platform. The lock file is an audit output, not an input replay mechanism.

A successful bundle covers declared container references; it is not a complete inventory of software that might execute. Runtime downloads, host tools, CWL engine dependencies, and packages Trivy cannot detect are outside its scope. Docker hints describe possible execution environments, not proof of an actual run. The workflow inventory therefore explicitly declares its composition incomplete. Image SBOMs are retained without merging away package or distribution metadata needed by Trivy.

## Development

```sh
pip install -e '.[test]'
pytest
hatch run dev:typecheck
hatch run dev:ruff check src tests
hatch run dev:ruff format --check src tests
hatch run dev:security
pip install -r requirements-docs.txt
mkdocs build --strict
```

Verified with Trivy 0.74.0 against `alpine:3.21` on `linux/amd64`.

Tests use controlled scanner responses and require no registry access. Real Trivy scanning is a separate integration check. See [architecture](docs/explanation/architecture.md).

## License

[![Apache License, Version 2.0](https://img.shields.io/badge/license-Apache%20License%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)
