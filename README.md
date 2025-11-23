# Wazuh Plugins Build System

## Project Purpose

This repository is a Wazuh Plugins Build System designed to automate the compilation, packaging, and distribution of security tools that complement Wazuh deployments. The main goal is to provide a unified, multi-architecture build pipeline that creates native packages for Suricata IDS, YARA malware scanner, and repackaged Wazuh agents.

## Key Features

- **Multi-platform support**: Builds for Linux (amd64/arm64) and macOS (amd64/arm64)
- **Dependency management**: Handles complex build dependencies automatically
- **Package standardization**: Creates consistent packages across different tools
- **CI/CD automation**: Fully automated build and release pipeline
- **Security tool integration**: Packages security tools specifically for Wazuh environments

## Directory Structure

The project is organized with a `builders/` directory that contains specific builders for different security tools. Each builder follows a consistent structure:

- `build/`: Contains the main build script and its modules.
- `system/`: Holds system-level scripts.
- `tests/`: Contains test scripts for the builder.
- `utils/`: Includes utility scripts.

## Usage

To initiate a build, run the main runner script with a builder's configuration file:

```bash
python3 .github/scripts/run_builder.py builders/<builder_name>/config.yaml
```

## CI/CD Automation

The GitHub Actions workflows automate the entire build and release process, using a matrix strategy to run builds for different platforms and architectures.
