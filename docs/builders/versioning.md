# Builder Versioning Strategy

We no longer resolve upstream release tags at build time. Instead, each builder
uses its `version.txt` file as the single source of truth for the upstream
software version. The `.github/scripts/run_builder.py` helper reads the version
from `version.txt` and exposes it to the build script through the
`PIPELINE_VERSION` environment variable.

## YARA

* `builders/yara/version.txt` holds the exact upstream tag (e.g. `yara-4.5.4`).
* `builders/yara/scripts/build_native.py` downloads the matching tarball by
  referencing `PIPELINE_VERSION`
  (``https://github.com/VirusTotal/yara/archive/refs/tags/${PIPELINE_VERSION}.tar.gz``).
* The scripted resolver was deleted because it provided duplicate behavior and
  required network calls.

## Suricata

* `builders/suricata/version.txt` is read by run_builder and forwarded via
  `PIPELINE_VERSION`.
* The build script builds tags of the form `suricata-${PIPELINE_VERSION}` and
  no longer shells out to a resolver.

### Practical implications

* Updating to a new upstream version only requires editing `version.txt`.
* Builds are deterministic because they do not call the GitHub API to discover
  tags.
* CI developers should ensure `version.txt` is updated whenever a new release
  needs to be built.
