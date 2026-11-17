# Build and transfer a local VOLT demo

This path builds one native Docker image for the machine that will run the demo. Use a clean, committed checkout. The package contains the exact source archive and image, records the selected platform and image ID, and validates the saved image before Docker imports it.

The portable demo package is **checksum-only local demo material**. Its checksums detect accidental corruption and its image admission binds the image to the captured source revision and platform. It is not signed and does not provide publisher authenticity. For signed release material, use the separate release archive verification instructions.

## Requirements

- Docker Engine or Docker Desktop with Buildx and the target architecture available natively
- Python 3.13 or later, Node.js 24, npm, and `uv`
- A clean Git checkout of VOLT

The default CE base and Debian packages are pinned separately for `linux/amd64` and `linux/arm64`. Builds select one target explicitly; the helper fails if the resulting image does not match it. The workflow exercises both architectures on native hosted runners. A successful `--check` alone does not prove an image can run on the selected architecture.

## Build a package

From the repository root, choose the platform that Docker reports for the Linux engine that will run the containers:

```sh
docker info --format '{{.OSType}}/{{.Architecture}}'
```

Build for that platform. Apple Silicon commonly reports `linux/arm64`:

```sh
python3 tools/release/portable_demo.py build \
  --platform linux/arm64 \
  --output "$PWD/volt-portable-demo-arm64.tar.gz"
```

For an amd64 Linux engine, use `linux/amd64` and an architecture-named output file. The helper builds with the pinned platform-specific DefectDojo CE child digest, captures the clean source revision, saves the local Docker image, and validates the image archive before creating the package.

## Verify and load on the destination

Transfer the `.tar.gz` package to a machine with a matching Docker platform. Before loading, verify its package inventory, image structure, image ID, source snapshot and platform:

```sh
python3 tools/release/portable_demo.py verify \
  --archive ./volt-portable-demo-arm64.tar.gz
```

Then verify again and import the image:

```sh
python3 tools/release/portable_demo.py load \
  --archive ./volt-portable-demo-arm64.tar.gz
```

The loader checks Docker's resulting image ID, platform and source labels against the package metadata. The JSON result prints the immutable image ID to pass to the local Compose installer. Continue with the **Local demo** instructions in [`deploy/compose/README.md`](../deploy/compose/README.md) to initialize the demo, sign in, and operate it. Use a disposable local directory and data; the installer cleanup command owns only that named demo instance.

Do not treat this checksum-only package as a signed release or use it to make a production deployment claim. The package is intended for local demo transfer and testing.
