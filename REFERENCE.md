# Cthaeh Reference

Detailed technical reference. For quick start and overview, see [README.md](README.md).

## Check Categories (97 heuristics)

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Device security** | IoCreateDevice vs Secure, symlink+no ACL, WDM vs WDF | Weak access controls |
| **IOCTL surface** | Dispatched IOCTL count, METHOD_NEITHER, FILE_ANY_ACCESS | Attack surface size |
| **Dangerous primitives** | MSR R/W, CR access, physical memory mapping, port I/O | Kernel-level capabilities |
| **BYOVD** | Process open + terminate, token steal, DSE bypass, arb R/W, kernel execute | Weaponizable drivers |
| **Validation gaps** | No ProbeForRead/Write, no auth imports, unchecked memcpy | Missing input validation |
| **USB/BT** | URB construction, HCI passthrough, eFuse access | Hardware control passthrough |
| **Firmware** | UEFI variables, HAL bus data, hardcoded crypto keys | Firmware manipulation |
| **Vendor context** | CNA status, bounty programs, driver class ranking | Vuln assignment likelihood |
| **Compound scoring** | MSR+PhysMem=god-mode, IOCTL+no-auth+named-device=easy target | Multi-primitive combinations |
| **Kernel Rhabdomancer** | Per-function candidate point mapping, call graph from IOCTL dispatch | Pinpoints *where* dangerous APIs are called |
| **Vuln pattern** | IOCTL surface + dangerous primitive + missing validation | Pattern from 8 confirmed vulns |
| **WDAC block policy** | Win10/Win11 driver block policy by SHA256 + filename | Skips already-blocked drivers |
| **LOLDrivers** | SHA256 cross-ref against HolyGrail's curated list | Flags known LOLDrivers |
| **Comms capability** | IoCreateDevice, IoCreateSymbolicLink, FltRegisterFilter | User-mode bridge detection |
| **PPL killer** | ZwTerminateProcess + ZwOpenProcess combo | Protected process termination |
| **Memory corruption** | UAF, double-free, free-without-null in IOCTL dispatch paths | Instruction-level pattern analysis |
| **IORING surface** | IORING APIs, shared memory section patterns | Novel kernel attack surface |
| **Killer driver** | Process enum+kill, callback removal, minifilter unload, EDR strings | EDR/AV termination patterns |
| **Bloatware/OEM** | Consumer OEM vendor boost, utility strings, PE age | Prioritizes weak vendors |
| **Double-fetch / TOCTOU** | User buffer pointer read multiple times without local capture | Race conditions in IOCTL handlers |
| **On-disk offset trust** | Parsed offsets without bounds checking | Trusted offset → OOB read/write |
| **Framework detection** | WDF vs WDM detection, auto-adjusts scoring | WDF less noise, WDM more scrutiny |

## Anti-Pattern Tags

Findings are tagged with KernelSight anti-patterns (AP1-AP6):

| Tag | Pattern | CVE frequency |
|-----|---------|---------------|
| AP1 | Trusting user-supplied lengths | ~60% of driver CVEs |
| AP2 | Missing synchronization on shared state | ~14% |
| AP3 | Trusting on-disk/file-embedded offsets | FS/minifilter bugs |
| AP4 | Exposing physical memory or MSR access | God-mode primitives |
| AP5 | No IOCTL auth / open device ACLs | Easy targets |
| AP6 | Double-fetch / TOCTOU on user buffers | Race conditions |

## All CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--running-only` | ON | Only scan loaded drivers (Windows) |
| `--all` | OFF | Scan all drivers |
| `--hw-check` | OFF | Post-triage hardware presence check |
| `--device-check` | OFF | Post-triage device DACL check |
| `--device-check-min-score` | 75 | Min score for device check |
| `--research` | OFF | hardware_absent is informational only |
| `--workers N` | auto | Parallel Ghidra instances |
| `--no-prefilter` | OFF | Disable pefile pre-filter |
| `--max-size` | 5 | Max driver size in MB for pre-filter |
| `--no-json` | OFF | Disable JSON output |
| `--no-report` | OFF | Disable markdown report |
| `--report-top` | 20 | Drivers in markdown report |

## Environment Variables

- `GHIDRA_HOME` - Path to Ghidra installation
- `CTHAEH_FP_PATH` - Override path to investigated.json
- `CTHAEH_DTA_PATH` - Override path to .gdt data type archive

## Files

| File | Purpose |
|------|---------|
| `driver_triage.py` | Ghidra headless script (97 checks) |
| `run_triage.py` | Orchestrator (parallel, prefilter, running-only, explain) |
| `prefilter.py` | Fast PE import pre-filter |
| `extract_driverstore.py` | Extracts third-party .sys from DriverStore |
| `scoring_rules.yaml` | All scoring weights and thresholds |
| `apply_dta.py` | Ghidra pre-script: loads Talos DTA |
| `download_dta.py` | Downloads the Talos .gdt file |
| `hw_check.py` | Hardware presence check via PnP enumeration |
| `device_check.py` | Device object DACL check |
| `cna_vendors.json` | CNA status + bounty URLs per vendor |
| `driver_cves.json` | Prior CVE history per driver family |
| `investigated.json` | Already-analyzed drivers (skipped on scan) |
| `policies/` | WDAC block policies + LOLDrivers data |
| `test_regression.py` | Regression tests |
