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
│   └── yara/
│       ├── config.yaml
│       ├── Dockerfile
│       ├── scripts/
│       ├── rules/
│       ├── version.txt
│       └── release.txt
├── .github/
│   ├── scripts/run_builder.py       # Utility that reads config.yaml and executes the declared steps
│   ├── workflows/builders.yaml      # GitHub Actions workflow that iterates over every builder
│   └── workflows/builder-cache.yaml # Nightly job that refreshes Buildx caches for all builders
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

## Building Suricata, Yara, and similar appliances

Some deployments prefer to ship companion services—such as [Suricata](https://suricata.io/) for IDS or [Yara](https://virustotal.github.io/yara/) for file scanning—next to Wazuh so detections and enrichments stay close to the data plane. These builds live under `builders/<appliance>` and follow a shared contract so additional tools can be onboarded without rethinking the layout.

1. **Place Docker assets** – Drop the `Dockerfile`, helper scripts, and configuration templates inside `builders/<name>/`. Keep runtime artifacts (rulesets, signatures, etc.) versioned so CI can reproduce the image. The Suricata and Yara folders already contain fake Dockerfiles, entrypoints, and rule packs to illustrate how supporting files should be laid out.
2. **Use Docker Buildx** – Each appliance should be built via Buildx to support multi-architecture deployments **and** to emit binaries that later get attached to GitHub Releases. A canonical workflow that mirrors CI looks like:
   ```bash
   docker buildx create --name wazuh-plugins --use
   docker buildx build builders/suricata \
       --platform linux/amd64,linux/arm64 \
       --target artifacts \
       --output type=local,dest=builders/suricata/dist/linux-buildx
   ```
   Replace `suricata` with `yara` (or the name of any future appliance) to reuse the same invocation. The `artifacts` target
   exposes files placed under `/release` inside the Dockerfile and writes them to `builders/<name>/dist/linux-buildx/` so they
   can be zipped and published.
3. **Build macOS payloads from the same config** – GitHub Actions fans out to dedicated macOS runners that call `.github/scripts/run_builder.py --builder-mode native --artifact-triplet <mac target> builders/<name>/config.yaml`. The helper respects the exact same `config.yaml` that Linux uses, executes the declared lint/test/build steps, and writes artifacts under `builders/<name>/dist/<triplet>/`. Native builds rely on a `native_build_script` (defaulting to `scripts/build-native.sh`) that receives `ARTIFACT_DEST`, `ARTIFACT_TRIPLET`, and `PIPELINE_VERSION` so the same source tree can be packaged per platform without Docker. The two supported triplets are:
   - `macos-13` / `amd64` → `macos-amd64`
   - `macos-14` / `arm64` → `macos-arm64`
4. **Document build arguments** – Capture supported `--build-arg`s (e.g., `SURICATA_VERSION`, `RULE_BUNDLE`) inside `builders/<name>/README.md` so users know how to customize the resulting bundle.
5. **Define release metadata** – Every appliance folder includes a `config.yaml` (the pipeline contract consumed by automation), a `version.txt` (single source of truth for build arguments), and a `release.txt` (the Git tag/Release version). `.github/scripts/run_builder.py` consumes these files, runs lint/test/build steps locally or inside CI, and drops outputs into `dist/<triplet>/` whether the run targets Linux (`linux-buildx`) or macOS (`macos-*`).
6. **Let GitHub Actions do the heavy lifting** – `.github/workflows/builders.yaml` discovers each `builders/*/config.yaml` on every push/PR, provisions Docker Buildx on Ubuntu to produce the `linux-buildx` archive, and fans out to `macos-13` and `macos-14` runners (amd64 and arm64 respectively) that invoke `run_builder.py --builder-mode native --artifact-triplet <triplet>`. When the workflow runs on `main` every job archives its target-specific `dist/<triplet>/` folder, tags a GitHub Release using `<name>-v$(cat release.txt)`, and uploads the tarballs via `softprops/action-gh-release`. A companion workflow (`.github/workflows/builder-cache.yaml`) runs nightly or on demand with `--cache-only` to refresh Buildx caches stored under `ghcr.io/adorsys-gis/wazuh-plugins-<name>/cache`, keeping future builds quick without publishing runtime images.

> **Future tooling**: When introducing additional inspection or enrichment services, keep them under `builders/` and adopt the Buildx workflow above. Doing so ensures that CI/CD jobs can enumerate all appliances and publish them with consistent tagging semantics.

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
