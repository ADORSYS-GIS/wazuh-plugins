# Suricata builder

Rules are sourced from the Emerging Threats “emerging-all.rules” feed for
Suricata 8.0.2 and pinned via `builders/suricata/rules/source.json` (checksum
and URL).

## Fetch rules

```bash
python builders/suricata/scripts/fetch_suricata_rules.py --flavor open
```

This downloads `emerging-all.rules`, verifies the SHA256, and caches it under
`builders/suricata/rules-cache/open-8.0.2-all/open/`.

Environment overrides:

- `RULE_BUNDLE`: Use a custom rules directory instead of the cached bundle.
- `ALLOW_RULE_DOWNLOAD=1`: Let the builder auto-fetch using the pinned metadata
  when the cache is missing.
- `RULES_CACHE`: Override the cache directory (default:
  `builders/suricata/rules-cache`).
- `RULES_FLAVOR`: Defaults to `open` (only option today).

The builder records the rules source/tag/flavor in `BUILDINFO.txt` inside the
package payload.
