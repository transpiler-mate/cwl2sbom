# Generate

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

After provisioning the appropriate Trivy databases in an offline environment, scan each `images/*.cdx.json` separately:

```sh
trivy sbom --skip-db-update --skip-java-db-update --offline-scan \
  --format json --output vulnerabilities.json image.cdx.json
```

Apply your pinned Trivy version's network settings as described in its [offline documentation](https://trivy.dev/docs/latest/guide/advanced/air-gap/). `--offline-scan` alone does not disable database updates. The plugin generates inventories, not vulnerability verdicts.

## Scope and reproducibility

A tag is resolved by Trivy during inspection. The lock records the repository digest(s) and image configuration ID reported by that inspection, together with the requested platform. It does not pre-resolve tags or rewrite CWL. A reported repository digest can identify a multi-platform index: it must not be mistaken for a selected child manifest digest. For subsequent reproducible invocations, use digest-pinned references and the same platform. The lock file is an audit output, not an input replay mechanism.

A successful bundle covers declared container references; it is not a complete inventory of software that might execute. Runtime downloads, host tools, CWL engine dependencies, and packages Trivy cannot detect are outside its scope. Docker hints describe possible execution environments, not proof of an actual run. The workflow inventory therefore explicitly declares its composition incomplete. Image SBOMs are retained without merging away package or distribution metadata needed by Trivy.

