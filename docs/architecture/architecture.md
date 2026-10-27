# Build System Architecture

## Builders Directory Structure

The `builders/` directory is organized with a consistent structure for each builder:

- `build/`: Contains the main build script (`main.py`) and its modules. This is the entry point for building a specific tool.
- `system/`: Holds system-level scripts, such as `postinstall.sh` and service startup scripts.
- `tests/`: Contains test scripts for the builder.
- `utils/`: Includes utility scripts, like rule fetchers.

## Common Modules

The `builders/common/` directory contains shared Python code (`wazuh_build`) used by all builders. This promotes code reuse and consistency across different tools.

### Purpose of Common Modules

The common modules handle tasks such as:

- Dependency resolution
- Packaging
- Executing shell commands

This shared codebase ensures that all builders follow the same best practices and standards.
