# Wazuh Plugins Python Codebase Refactoring Proposal

Based on the analysis of the `builders` directory, specifically the `build_native.py` scripts for Suricata, Wazuh Agent, and Yara, the following refactoring is proposed to improve maintainability, reduce code duplication, and enhance consistency.

## 1. Factorization of Common Patterns

The following duplicate patterns have been identified and will be consolidated into shared modules within `builders/common/python/wazuh_build/`:

### A. Build Utilities (`wazuh_build.utils` or new `wazuh_build.build_utils`)

* **Path Manipulation:** `_prepend_path_if_missing` (Suricata, Yara) -> `wazuh_build.utils.prepend_path`.
* **Job Detection:** `detect_jobs` (Suricata, Yara) -> `wazuh_build.utils.detect_jobs`.
* **Environment Helpers:** `_bool_env` (Suricata, Yara) -> `wazuh_build.utils.bool_env`.
* **Permissions:** `fix_permissions`, `_should_be_executable` (All) -> `wazuh_build.utils.fix_permissions`.

### B. Validation (`wazuh_build.validation` or `wazuh_build.deps`)

* **Tool Requirements:** `require_tools` (All) -> `wazuh_build.deps.require_tools`.
* **Library Requirements:** `require_libraries`, `_has_magic_header` (Suricata, Yara) -> `wazuh_build.deps.require_libraries`.

### C. Rule Management (`wazuh_build.rules`)

* **Metadata:** `load_rules_metadata` (Suricata, Yara).
* **Bundle Resolution:** `resolve_rule_bundle` (Suricata, Yara).
* **Logic:** Consolidate logic for fetching and caching rules.

### D. Download & Unpack (`wazuh_build.download`)

* **Download:** `download_and_unpack` (Suricata, Yara).
* **Tarball Handling:** `_strip_components` (Suricata, Yara).

### E. Packaging & Metadata (`wazuh_build.packaging`, `wazuh_build.metadata`)

* **Release Packaging:** `package_release` (All) has high overlap. Create a configurable `package_release` function in `wazuh_build.packaging` that accepts component-specific parameters.
* **Metadata:** `write_metadata` (All) -> `wazuh_build.metadata.write_build_info`.
* **Revision Header:** `write_revision_header` (Suricata, Yara) -> `wazuh_build.metadata.write_revision_header`.

## 2. Addressing Inconsistencies

* **Platform Logic:** Centralize platform checks in `wazuh_build.platform`. Use `wazuh_build.platform.is_linux()` etc. instead of repeated string comparisons.
* **Error Handling:** Standardize on raising `SystemExit` with clear messages for fatal errors, or use a custom `BuildError` exception class.
* **Configuration:** Ensure `BuilderConfig` is used consistently.

## 3. Enhanced Structure

The proposed directory structure for `builders/common/python/wazuh_build/`:

```
builders/common/python/wazuh_build/
├── __init__.py
├── builder.py       # New: BaseBuilder class (optional, for OOP approach)
├── config.py        # Existing: Configuration management
├── deps.py          # Existing: Dependency management (apt, brew, tools, libs)
├── download.py      # New: Download and unpack utilities
├── metadata.py      # New: Build info and revision header generation
├── packaging.py     # Existing: Packaging logic (deb, rpm, dmg, tarball)
├── platform.py      # Existing: Platform detection
├── rules.py         # New: Rule management
├── sbom.py          # Existing: SBOM generation
├── shell.py         # Existing: Shell command execution
└── utils.py         # Existing: General utilities (path, hashing, etc.)
```

## 4. Security and Performance

* **Input Validation:** Ensure all external inputs (env vars, config) are validated.
* **Safe Extraction:** Ensure `tarfile` extraction is safe (already partially handled by `_strip_components`, but can be hardened).
* **Error Handling:** Wrap shell executions in try/except blocks where appropriate to provide better context on failure.

## 5. Implementation Plan

1. **Create New Modules:** Create `rules.py`, `download.py`, `metadata.py`.
2. **Refactor Existing Modules:** Update `deps.py`, `utils.py`, `packaging.py` with consolidated functions.
3. **Update Builders:** Refactor `builders/{suricata,wazuh-agent,yara}/scripts/build_native.py` to import and use the shared functions.
4. **Verify:** Ensure builds still work as expected (requires running builds or unit tests).
