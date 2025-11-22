# YARA builder

This builder compiles YARA and packages it with a curated rule bundle from
[YARA Forge](https://github.com/YARAHQ/yara-forge). Rule downloads are pinned to
a specific release tag and verified via checksum to keep the supply chain
predictable.

## Rule bundles

- Metadata lives in `builders/yara/rules/source.json` and pins tag `20251116`
  plus checksums for the `core`, `extended`, and `full` bundles.
- Fetch rules into a local cache (defaults to `builders/yara/rules-cache/`):
  ```bash
  python builders/yara/scripts/fetch_yara_rules.py --flavor full
  # or core / extended
  ```
- The builder looks for cached rules under
  `rules-cache/<tag>/<flavor>/`. If missing, either:
  - Set `ALLOW_RULE_DOWNLOAD=1` to let the build auto-fetch using the pinned
    metadata, or
  - Point `RULE_BUNDLE=/path/to/your/rules` to use an existing directory or
    `.yar` file.

Additional env overrides:

- `RULES_CACHE`: change the cache directory (defaults to
  `builders/yara/rules-cache`).
- `RULES_FLAVOR`: choose `core`, `extended`, or `full` (default: `full`).
- `RULE_BUNDLE`: bypass the cache/metadata and use a custom path.

## Building

```bash
python .github/scripts/run_builder.py \
  --artifact-triplet linux-amd64 \
  builders/yara/config.yaml
```

Artifacts are written to `builders/yara/dist/<triplet>/artifacts/` and include
SBOMs plus platform packages. The bundled rule flavor and tag are recorded in
`BUILDINFO.txt` inside the payload.
