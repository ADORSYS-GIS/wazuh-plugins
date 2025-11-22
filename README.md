# Wazuh Plugins

A curated collection of automation and integration plugins that extend the [Wazuh](https://wazuh.com) security platform. The goal of this repository is to make it simple to connect Wazuh to the rest of your security stack—threat intel feeds, ticketing systems, chat tools, or custom data sources—without having to re-implement boilerplate collectors and response logic every time.

> **Why it exists**: Modern SOC workflows rarely live entirely inside a single product. These plugins provide reusable building blocks so that teams can forward alerts, enrich events, and trigger remediation actions directly from Wazuh.

## Highlights

- **Connector-first design** – Each plugin wraps a specific integration (for example, ServiceNow, Slack, or an internal CMDB) behind a consistent interface so you can swap providers without touching the rule logic.
- **Event enrichment pipeline** – Normalizes alerts from the Wazuh analysisd queue, decorates them with threat-intel context, and publishes the result back into Wazuh or any downstream system.
- **Response automation hooks** – Exposes lightweight playbook steps (quarantine host, open ticket, send chat message, etc.) that can be invoked from decoders, rules, or the Wazuh API.
- **Deployment agnostic** – Works whether your Wazuh managers live on-premises or inside Kubernetes. Plugins run as containers, systemd services, or Wazuh internal daemons.
- **Security aware** – Ships with least-privilege API scopes, encrypted secrets management, and audit logging so integrations remain compliant.

## Repository layout

```
.
├── plugins/               # Home for individual integration packages (to be populated)
├── packages/              # Shared libraries (e.g., auth, logging, telemetry)
├── examples/              # Sample policies demonstrating plugin usage
├── docs/                  # Detailed design documents, diagrams, and how-tos
├── builders/              # Docker Buildx contexts for Suricata, Yara, and future appliances
│   ├── suricata/
│   │   ├── config.yaml    # CI/CD pipeline contract for Suricata builds
│   │   ├── Dockerfile     # Multi-stage build that emits release artifacts under /release
│   │   ├── scripts/       # Entry points plus regression helpers referenced by config.yaml
│   │   ├── rules/         # Fake Suricata rule files for local testing
│   │   ├── version.txt    # Source of truth for the Buildx inputs (base version, args, etc.)
│   │   └── release.txt    # Release tag written to GitHub when a binary archive ships
│   ├── yara/
│   │   ├── config.yaml
│   │   ├── Dockerfile
│   │   ├── scripts/
│   │   ├── rules/
│   │   ├── version.txt
│   │   └── release.txt
│   └── wazuh-agent/
│       ├── config.yaml
│       ├── scripts/
│       ├── version.txt
│       ├── release.txt
│       └── README.md
├── .github/
│   ├── scripts/run_builder.py       # Utility that reads config.yaml and executes the declared steps
│   ├── scripts/package_artifacts.py # Gathers packaged artifacts for upload in CI
│   └── workflows/builders.yaml      # GitHub Actions workflow that iterates over every builder
└── README.md
```

> The tree above describes the intended structure. The repository currently only contains the README so contributors can align on goals before code lands.

## Getting started

1. **Clone the repository**
   ```bash
   git clone https://github.com/<org>/wazuh-plugins.git
   cd wazuh-plugins
   ```
2. **Plan your plugin** – Decide whether you are building a collector (ingest data into Wazuh), an enricher (augment existing alerts), or an action (trigger an external workflow). Use the `docs/plugin-template.md` (coming soon) as a checklist.
3. **Bootstrap the runtime** – Each plugin should expose a `main.py` (for Python) or `main.go` (for Go) entry point plus a `plugin.yaml` manifest containing metadata (name, version, permissions, configuration schema, and health checks).
4. **Wire it into Wazuh** – Register the plugin by adding a `<plugin>` block inside `ossec.conf` or deploy it next to Wazuh using Docker/Kubernetes. Provide environment variables or secrets via your orchestration platform.

## Building Suricata, Yara, Wazuh agent, and similar appliances

Some deployments prefer to ship companion services—such as [Suricata](https://suricata.io/) for IDS, [Yara](https://virustotal.github.io/yara/) for file scanning, or upstream-packaged Wazuh agents—next to Wazuh so detections and enrichments stay close to the data plane. These builds live under `builders/<appliance>` and follow a shared contract so additional tools can be onboarded without rethinking the layout.

1. **Place Docker assets** – Drop the `Dockerfile`, helper scripts, and configuration templates inside `builders/<name>/`. Keep runtime artifacts (rulesets, signatures, etc.) versioned so CI can reproduce the image. The Suricata and Yara folders already contain fake Dockerfiles, entrypoints, and rule packs to illustrate how supporting files should be laid out.
   - The YARA builder now pulls rules from the pinned [YARA Forge](https://github.com/YARAHQ/yara-forge) release declared in `builders/yara/rules/source.json`; run `python builders/yara/scripts/fetch_yara_rules.py --flavor full` (or set `ALLOW_RULE_DOWNLOAD=1`) to populate the cache before building, or point `RULE_BUNDLE` to your own rules.
   - The Suricata builder pulls Emerging Threats open “emerging-all.rules” for Suricata 8.0.2 per `builders/suricata/rules/source.json`; run `python builders/suricata/scripts/fetch_suricata_rules.py --flavor open` (or set `ALLOW_RULE_DOWNLOAD=1`) to populate the cache, or set `RULE_BUNDLE` to a custom rules path.
2. **Run native builds** – Each appliance is compiled natively per target architecture using the shared `native_build_script` (defaulting to `scripts/build_native.py`). The helper receives `ARTIFACT_DEST`, `ARTIFACT_TRIPLET`, and `PIPELINE_VERSION` so the same source tree can be packaged per platform without Docker. Linux artifacts land in `builders/<name>/dist/linux-amd64` and `builders/<name>/dist/linux-arm64` when run on Ubuntu 24.04 amd64 and arm runners respectively.
3. **Build macOS payloads from the same config** – GitHub Actions fans out to dedicated macOS runners that call `.github/scripts/run_builder.py --artifact-triplet <mac target> builders/<name>/config.yaml`. The helper respects the exact same `config.yaml` that Linux uses, executes the declared lint/test/build steps, and writes artifacts under `builders/<name>/dist/<triplet>/`. The two supported triplets are:
   - `macos-13` / `amd64` → `macos-amd64`
   - `macos-14` / `arm64` → `macos-arm64`
4. **Document build arguments** – Capture supported `--build-arg`s (e.g., `SURICATA_VERSION`, `RULE_BUNDLE`) inside `builders/<name>/README.md` so users know how to customize the resulting bundle.
5. **Define release metadata** – Every appliance folder includes a `config.yaml` (the pipeline contract consumed by automation), a `version.txt` (single source of truth for build arguments), and a `release.txt` (the Git tag/Release version). `.github/scripts/run_builder.py` consumes these files, runs lint/test/build steps locally or inside CI, and drops outputs into `dist/<triplet>/` whether the run targets Linux (`linux-*`) or macOS (`macos-*`).
6. **Let CI do the heavy lifting** – `.github/workflows/builders.yaml` discovers each `builders/*/config.yaml` on every push/PR, runs native builds on `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64), and fans out to `macos-13` and `macos-14` runners. When the workflow runs on `main` every job archives its target-specific `dist/<triplet>/` folder, tags a GitHub Release using `<name>-v$(cat release.txt)`, and uploads the tarballs via `softprops/action-gh-release`. The same `run_builder.py` and `package_artifacts.py` entry points can be invoked from other CI systems (Jenkins, Tekton, GitLab) or locally; see below.

> **Future tooling**: When introducing additional inspection or enrichment services, keep them under `builders/` and adopt the native workflow above. Doing so ensures that CI/CD jobs can enumerate all appliances and publish them with consistent tagging semantics.

## Configuration conventions

All plugins share a minimal contract:

| Key | Description |
| --- | --- |
| `id` | Unique identifier used for logging and metrics. |
| `type` | `collector`, `enricher`, or `action`. Determines the lifecycle hooks that must be implemented. |
| `schedule` | For collectors, a cron expression or interval that defines polling cadence. |
| `inputs` | List of Wazuh event types, API endpoints, or custom triggers to listen for. |
| `outputs` | One or more destinations (Wazuh queue, HTTP webhook, message bus, ticketing API). |
| `secrets` | Reference to the credential bundle in your vault/Kubernetes secret. |

## Development workflow

1. Create a feature branch per plugin or enhancement.
2. Add or update automated tests under `<plugin>/tests/` so new integrations can be validated without reaching production systems.
3. Run `make lint test` (targets will be added alongside the first plugin) before opening a pull request.
4. Document configuration parameters and expected behavior inside `docs/plugins/<name>.md`.

## Testing philosophy

- **Unit tests** keep logic deterministic by mocking external APIs.
- **Contract tests** spin up lightweight containers (e.g., LocalStack for AWS) to verify that authentication scopes and payloads remain compatible with upstream services.
- **End-to-end smoke tests** run in CI using real Wazuh events to make sure decoders, rules, and plugin handlers work together.

## Roadmap

- Publish a plugin SDK (Python) so integrations can share logging, metrics, and retry helpers.
- Ship reference connectors for Jira, ServiceNow, Slack, and AWS Security Hub.
- Provide Helm charts and Ansible roles for deploying plugins alongside Wazuh managers.
- Build a configuration UI in the Wazuh dashboard to enable/disable plugins without editing XML.

## Contributing

Contributions are welcome! Please open an issue describing the integration or improvement you have in mind. When submitting a pull request, include:

1. A clear description of the problem being solved.
2. Tests that cover new functionality or regressions.
3. Documentation updates (README, docs/plugins/<name>.md, sample configuration).

## License

Unless noted otherwise, all code in this repository is made available under the MIT License. See `LICENSE` for the full text.
## Running builders locally or in other CI systems

You do not need GitHub Actions to execute the appliance pipelines. The helper scripts live in-repo and work anywhere Python 3.8+ is available.

- **Prereqs**: Python 3.8+, `pyyaml` (`pip install -r .github/workflows/venv-requirements.txt`), `curl`, `tar`, `make`, `pkg-config`, and a package manager (`apt` or Homebrew) so the builder scripts can install dependencies declared in `builders/*/config.yaml`. If you want a consistent environment, pull the cache image `ghcr.io/<org>/<repo>/cache-builders:latest` and run inside it.
- **Example (Linux/macOS host or Jenkins/Tekton step)**:
  ```bash
  python3 -m venv .venv && source .venv/bin/activate
  pip install -r .github/workflows/venv-requirements.txt
  export PIPELINE_VERSION="$(cat builders/yara/version.txt)"
  export PIPELINE_COMMIT="$(git rev-parse HEAD)"
  export PIPELINE_REF="$(git rev-parse --abbrev-ref HEAD)"
  python .github/scripts/run_builder.py --artifact-triplet linux-amd64 builders/yara/config.yaml
  python .github/scripts/package_artifacts.py yara linux-amd64
  ```
  Swap builder name/triplet as needed (e.g., suricata, macos-arm64). Artifacts land under `artifacts/<builder>-<version>-<triplet>/` ready for your CI to archive or publish.
- **Containers**: For parity with GitHub runners, start a job/pod using the cache image and run the same commands; no code changes are required because the build scripts read everything from `config.yaml` and environment variables.
