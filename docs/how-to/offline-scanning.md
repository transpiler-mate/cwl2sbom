# Scan exported SBOMs offline with Trivy

SBOM generation, artifact transport, and assessment are separate operations:

| Stage | Tool | Responsibility |
| --- | --- | --- |
| Generate | `transpiler-mate cwl2sbom` with Trivy | Inspect declared container images and write local SBOMs and identity metadata |
| Publish and retrieve | Your ORAS pipeline | Attach, distribute, and retrieve artifacts under your registry and trust policies |
| Assess | `trivy sbom` | Evaluate local SBOMs against a provisioned vulnerability database or license policy |

The commands below run outside the plugin. They use Trivy 0.74.0 flags; pin the scanner version in both preparation and offline environments and check `trivy sbom --help` when upgrading.

## 1. Prepare the scanner and database on a connected machine

Use a dedicated cache so the transferable database is independent of image-generation caches:

```sh
mkdir -p trivy-offline-cache
trivy image --cache-dir ./trivy-offline-cache \
  --disable-telemetry --skip-version-check --download-db-only
trivy --cache-dir ./trivy-offline-cache version --format json > trivy-version.json
```

If your scanner workflow needs the Java identification database, also provision it before transfer:

```sh
trivy image --cache-dir ./trivy-offline-cache \
  --disable-telemetry --skip-version-check --download-java-db-only
```

Preserve the cache layout, including `db/trivy.db` and `db/metadata.json` (and `java-db/` when provisioned). Bundle it with the version record:

```sh
tar -czf trivy-offline-db.tar.gz trivy-offline-cache trivy-version.json
sha256sum trivy-offline-db.tar.gz > trivy-offline-db.tar.gz.sha256
```

Transfer this archive, the matching Trivy executable, and the generated SBOM bundle using your established transport process. ORAS publication and retrieval remain outside `cwl2sbom`. No container images are needed at assessment time.

Trivy documents its external data requirements in [Connectivity and network considerations](https://trivy.dev/docs/latest/guide/advanced/air-gap/). Refresh the database on the connected side whenever you want to assess unchanged SBOMs against newer vulnerability information.

## 2. Restore and identify the inputs offline

In a dedicated assessment directory, verify and unpack your transferred archive:

```sh
sha256sum -c trivy-offline-db.tar.gz.sha256
tar -xzf trivy-offline-db.tar.gz
```

Place the retrieved plugin bundle at `./sbom`. Retain `images.lock.json` and `coverage.json`; use the lock's `sbom_sha256` values to verify each image SBOM and its recorded image/platform association. Apply your pipeline's artifact authenticity checks separately: a checksum detects changes but does not identify a trusted publisher.

Scan **`sbom/images/*.cdx.json`**, not just `workflow.cdx.json`. The workflow inventory links tools and containers; its referenced image SBOMs contain the package inventories. Trivy does not turn those references into a recursive bundle scan.

## 3. Generate vulnerability reports

Create an explicit empty configuration to avoid loading an unrelated `trivy.yaml` from the working directory. Use a controlled environment without inherited `TRIVY_*` overrides (such as a remote server, SBOM source, or VEX source).

```sh
printf '{}\n' > trivy-offline.yaml
mkdir -p reports
trivy sbom --config ./trivy-offline.yaml \
  --cache-dir ./trivy-offline-cache \
  --scanners vuln \
  --skip-db-update --skip-java-db-update \
  --offline-scan --skip-version-check --disable-telemetry \
  --format json --output reports/vulnerabilities.json \
  sbom/images/IMAGE.cdx.json
```

Replace `IMAGE.cdx.json` with a filename from `images.lock.json`. `--offline-scan` disables remote dependency identification; database updates, version checks, and telemetry have separate controls. Do not enable remote SBOM discovery, VEX sources, or client/server scanning for this local procedure. Enforce denied network egress in the assessment environment when strict offline operation is required.

For all image SBOMs, this Bash example retains separate reports and stops on scanner errors:

```bash
set -euo pipefail
shopt -s nullglob
sbom_files=(sbom/images/*.cdx.json)
if ((${#sbom_files[@]} == 0)); then
  echo 'No image SBOMs found; review coverage.json' >&2
  exit 2
fi
mkdir -p reports
for sbom_file in "${sbom_files[@]}"; do
  report_name=$(basename "$sbom_file" .cdx.json)
  trivy sbom --config ./trivy-offline.yaml \
    --cache-dir ./trivy-offline-cache --scanners vuln \
    --skip-db-update --skip-java-db-update \
    --offline-scan --skip-version-check --disable-telemetry \
    --format json --output "reports/${report_name}.vulnerabilities.json" \
    "$sbom_file"
done
```

These reporting commands use Trivy's default findings exit code of zero. For a separate CI gate, add `--severity HIGH,CRITICAL --exit-code 1`. That filters the report as well as controlling the findings exit status; keep an unfiltered report when you need the complete assessment. A nonzero status can also mean a scanner failure: retain logs and do not interpret every failure as a vulnerability finding. See the [Trivy SBOM CLI reference](https://trivy.dev/docs/latest/references/configuration/cli/trivy_sbom/).

## 4. Evaluate recorded licenses separately

The plugin preserves licenses detected during image inventory generation. It does not apply a license acceptance policy. Trivy can classify licenses already present in a local SBOM without a vulnerability database:

```sh
trivy sbom --config ./trivy-offline.yaml \
  --cache-dir ./trivy-offline-cache --scanners license \
  --skip-db-update --skip-java-db-update \
  --offline-scan --skip-version-check --disable-telemetry \
  --format json --output reports/licenses.json \
  sbom/images/IMAGE.cdx.json
```

Repeat for each image, using distinct output filenames as in the vulnerability loop. Use your organization's license classification configuration and acceptance criteria for a downstream gate; Trivy's default classifications are not a project-specific compatibility assessment.

Missing license information remains missing. Full license detection (`--license-full`) requires access to image or filesystem contents and is **not supported for SBOM targets**. `cwl2sbom` currently does not expose that generation option. Offline SBOM scanning cannot recover license texts that were not captured during generation. See [Trivy license scanning](https://trivy.dev/docs/latest/guide/scanner/license/).

## 5. Keep the assessment reproducible

Retain the SBOM checksums and lock file, scanner version, database metadata and archive checksum, policy/configuration and ignore files, scan time, logs, and reports. Database age affects what vulnerabilities can be found; a successful scan does not mean the database is current. A missing or incompatible database is a preparation error, not a clean scan.

Review `coverage.json` alongside the reports. Complete declared-container coverage does not include runtime downloads, host tools, or packages the generator did not detect. Refreshing a database can find newly disclosed vulnerabilities in existing package inventories; improving package or license detection requires regenerating the SBOMs.
