# Build Process

## Initiating a Build

A build is initiated by running the main runner script and passing a builder's configuration file:

```bash
python3 .github/scripts/run_builder.py builders/<builder_name>/config.yaml
```

## Role of `run_builder.py`

The `run_builder.py` script is responsible for executing the build process based on the configuration provided in the `config.yaml` file. It orchestrates the build pipeline, ensuring that all necessary steps are executed in the correct order.

## Configuration (`config.yaml`)

Each builder has a `config.yaml` file that defines its specific build pipeline, including:

- The path to the native build script (`build/main.py`).
- Any pre-build or post-build commands (e.g., linting, testing).
- Metadata for the package.

The `config.yaml` file is crucial for customizing the build process for each tool, allowing for flexibility and adaptability in the build system.
