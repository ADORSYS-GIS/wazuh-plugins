# Runtime Packaging Improvements

Both builders now stage their payloads under the final `/opt/wazuh/<component>`
path. This ensures binaries such as `/opt/wazuh/suricata/bin/suricata` and
`/opt/wazuh/yara/bin/yara` report the correct install path and work without
extra configuration.

## Key changes

### DESTDIR staging

* `build-native.sh` for each builder configures `--prefix=/opt/wazuh/<name>` and
  runs `make DESTDIR=${release_root} install`. The staging directory now contains
  the final filesystem layout.

### Bundled runtime libraries

* YARA bundles `libcrypto.so.1.1` and `libssl.so.1.1` inside
  `/opt/wazuh/yara/lib` and wraps `yara`/`yarac` with launcher scripts that set
  `LD_LIBRARY_PATH`.
* Suricata bundles `libnet.so.1` and `libjansson.so.4`. The `suricata*`
  binaries are wrapped so they load the bundled libraries before checking the
  system paths.

### Permissions and metadata

* After staging, both builders call `fix_component_permissions` to ensure all
  files are world-readable and entrypoints remain executable. This fixes
  `--dump-config` failures on systems where the staging process produced
  root-only files.
* Metadata and helper scripts now live inside the staged tree so they are
  packaged into the tarballs and `.deb` files automatically.

### Debian packages

* `.deb` creation simply copies the staged tree into `opt/wazuh/<name>`; the
  `Depends` list now excludes libraries we bundle ourselves (e.g.
  `libjansson4`).

### RPM packages

* Linux builds now generate `.rpm` artifacts alongside `.deb` and `.tar.gz`.
* We create lightweight RPM specs on the fly and run `rpmbuild` against the
  staged `/opt/wazuh/<name>` tree, producing architecture-specific packages
  for `x86_64` and `aarch64`.
* RPMs list `/opt/wazuh/<name>` as the single `%files` entry, so the full
  directory hierarchy is owned by the package and matches the tarball layout.
* RPM `Requires` are declared explicitly to mirror `.deb` runtime expectations
  (YARA: `glibc`, `file-libs`, `jansson`; Suricata: `glibc`, `libpcap`, `pcre2`,
  `libyaml`, `file-libs`, `lz4-libs`, `libcap-ng`).
