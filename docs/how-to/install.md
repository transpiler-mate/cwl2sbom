# Install

Install Python 3.10+ and Trivy separately. From the plugin checkout:

```sh
pip install transpiler-mate-runtime .
transpiler-mate cwl2sbom --help
```

The package registers the Transpiler-Mate entrypoint automatically. Supply `--trivy /path/to/trivy` when the executable is not on PATH. Registry authentication and credentials remain in Trivy configuration.
