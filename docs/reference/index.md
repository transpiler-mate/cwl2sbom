# Output reference

`images.lock.json` and `coverage.json` use plugin schema version 1. Paths in the lock are relative to the output directory. Each image record includes `reference`, requested `platform`, Trivy `repository_digests`, `image_ids`, `sbom`, `sbom_sha256`, `sbom_spec_version`, `bom_ref`, and `steps`.

The lock also records the source, entrypoint, generation timestamp, plugin version, and Trivy version. Repository digests are recorded as reported; no claim is made that they are platform child manifests.

Coverage statuses are `declared`, `uncovered`, and `not-applicable`. `complete` means no reachable tool lacks a usable container declaration, not that every runtime dependency was detected. All declared images must be successfully inspected for generation to succeed, including with `--allow-incomplete`.

The workflow SBOM uses CycloneDX 1.5 and references the unchanged image SBOMs with SHA-256 checksums. It does not flatten image package lists into one inventory. Scan each image SBOM separately.

See [options](../how-to/use-cli.md) and [Python API](api.md).
