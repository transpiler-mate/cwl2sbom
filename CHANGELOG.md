# Changelog

## Unreleased

- Document offline Trivy vulnerability and license assessment separately from generation and ORAS transport.

## 0.1.0

- Bootstrap cwl2sbom from the project template.
- Discover reachable CWL containers with inherited requirements and hints.
- Generate local Trivy CycloneDX SBOMs, workflow inventory, identity lock, and coverage report.
- Require an explicit platform; reject existing outputs and incomplete coverage by default.
