# Create a bundle

Add a DockerRequirement to a CWL tool with Transpiler-Mate software metadata:

```yaml
requirements:
  DockerRequirement:
    dockerPull: alpine:3.21
```

Then generate the bundle:

```sh
transpiler-mate cwl2sbom --platform linux/amd64 --output example-sbom workflow.cwl#main
```

Inspect `images.lock.json` to see the reported image identities and checksums. `coverage.json` records the scope of analysis. Publish the bundle with your existing ORAS process; no publication happens during generation.

To export a workflow with tools that lack container declarations, opt into `--allow-incomplete` and review its coverage report.
