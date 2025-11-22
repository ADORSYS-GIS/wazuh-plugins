# Wazuh agent builder

This builder repackages the upstream Wazuh agent binaries for Linux and macOS
into the same artifact layout used by the other appliances in this repository.
It does not compile from source; instead it downloads the signed agent packages
from `packages.wazuh.com` and stages their contents under the native install
paths (`/var/ossec` on Linux, `/Library/Ossec` on macOS).

## Build inputs

- `version.txt`: upstream agent version to fetch (e.g., `4.14.1`).
- `release.txt`: plugin release tag used when publishing artifacts.
- `PACKAGE_REVISION` (env, optional): package revision suffix (defaults to `1`),
  used to compose download URLs such as `wazuh-agent-<version>-<revision>.pkg`
  or `wazuh-agent_<version>-<revision>_<arch>.deb`.

## Running locally

```bash
python .github/scripts/run_builder.py \
  --artifact-triplet "$(uname | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  builders/wazuh-agent/config.yaml
```

Artifacts will land under `builders/wazuh-agent/dist/<triplet>/artifacts/` and
include tarballs plus platform-specific packages (deb/rpm on Linux, dmg on
macOS). Post-install tasks such as enrollment and service enablement remain
manual, matching the upstream packages.
