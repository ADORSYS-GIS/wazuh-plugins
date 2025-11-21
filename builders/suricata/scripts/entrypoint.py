#!/usr/bin/env python3
import os
import subprocess


def main() -> None:
    print(f"[suricata] Pretending to start Suricata {os.environ.get('SURICATA_VERSION', 'unknown')}")
    print("Custom rules mounted at /opt/suricata/custom-rules")
    subprocess.run(["/bin/sh", *os.sys.argv[1:]])


if __name__ == "__main__":
    main()
