# Architecture

Transpiler-Mate loads and normalizes CWL. The plugin serializes the resolved graph using cwl-utils, starts from the explicitly selected process, and traverses reachable tools. Effective requirements and hints are carried separately so required Docker declarations take precedence over hints; more local declarations override inherited declarations of the same category. Each invocation path is recorded, including repeated uses of one tool with different step requirements. Cycles and unresolved references fail.

The Trivy adapter runs a local executable using argument arrays, without a shell. It requests remote image inspection and an explicit platform, and leaves image fetching and caching to Trivy. No container is executed. Trivy's reported repository digests and image IDs are extracted from its CycloneDX metadata; a missing repository digest is an error. Output format and digest presence are checked, but this is not full validation of every Trivy CycloneDX field against its schema.

The plugin writes a new output directory exclusively and removes it on generation failure. Image SBOMs are preserved byte-for-byte. Workflow inventory edges connect the root to tool invocations and their containers; image documents remain separate with checksums. The inventory deliberately declares incomplete composition because static CWL analysis and package inspection cannot prove complete runtime coverage.

Generation may access registries and Trivy auxiliary data sources. Offline vulnerability scanning is a downstream operation with its own database lifecycle. OCI publication, attachment, signature policy, and retrieval belong to ORAS and the surrounding pipeline.
