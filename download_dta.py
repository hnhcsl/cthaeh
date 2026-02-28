#!/usr/bin/env python3
"""
Download the Cisco Talos Ghidra Data Type Archive (.gdt) for Windows drivers.

Source: https://github.com/Cisco-Talos/Windows-drivers-GDT-file
Blog:   https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/

Saves to data/windows_driver_types.gdt for use by apply_dta.py pre-script.
"""

import os
import sys
import hashlib

try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve  # Python 2 fallback

GDT_URL = "https://raw.githubusercontent.com/Cisco-Talos/Windows-drivers-GDT-file/main/Windows_Driver_functons.gdt"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "windows_driver_types.gdt")


def download():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if os.path.exists(OUTPUT_PATH):
        print("Already exists: %s" % OUTPUT_PATH)
        print("Delete it first if you want to re-download.")
        return

    print("Downloading Talos Windows Driver DTA...")
    print("  From: %s" % GDT_URL)
    print("  To:   %s" % OUTPUT_PATH)

    try:
        urlretrieve(GDT_URL, OUTPUT_PATH)
    except Exception as e:
        print("ERROR: Download failed: %s" % e)
        sys.exit(1)

    size = os.path.getsize(OUTPUT_PATH)
    print("Done. %d bytes written." % size)

    # Show SHA256 for verification
    with open(OUTPUT_PATH, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    print("SHA256: %s" % sha)


if __name__ == "__main__":
    download()
