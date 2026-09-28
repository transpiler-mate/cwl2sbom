<!--
Copyright 2026 Terradue

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Changelog

All notable changes to this archetype will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning for template releases.

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.1] - 2026-09-28

### Added

- Document offline Trivy vulnerability and license assessment separately from generation and ORAS transport.

### Changed

- Improved type annotations and internal code quality by addressing mypy, Ruff, and Bandit findings, without changing public APIs or runtime behavior.

## [0.1.0] - 2026-09-18

### Added

- Bootstrap cwl2sbom from the project template.
- Discover reachable CWL containers with inherited requirements and hints.
- Generate local Trivy CycloneDX SBOMs, workflow inventory, identity lock, and coverage report.
- Require an explicit platform; reject existing outputs and incomplete coverage by default.

[Unreleased]: https://github.com/Transpiler-Mate/cwl2sbom/compare/v0.1.1...develop
[0.1.1]: https://github.com/Transpiler-Mate/cwl2sbom/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Transpiler-Mate/cwl2sbom/releases/tag/v0.1.0
