# scan

A static file analyzer CLI for macOS. Pre-flight safety check for downloaded files before you open them.

`scan` inspects DMG, ZIP, PKG, `.app` bundles, and Mach-O binaries **without executing or installing anything**. It checks code signatures, Gatekeeper status, entitlements, linked libraries, persistence mechanisms, installer scripts, and more.

## Requirements

- macOS 15.0+
- Swift 6.0+ (Command Line Tools or Xcode)

## Install

### Download (prebuilt binary)

Grab the latest release from the [Releases page](https://github.com/carlosacchi/osx-virus-scan/releases):

```bash
curl -LO https://github.com/carlosacchi/osx-virus-scan/releases/latest/download/scan-macos.zip
unzip scan-macos.zip
xattr -c scan && chmod +x scan
mv scan /usr/local/bin/scan
```

> **Note:** macOS blocks unsigned binaries downloaded from the internet. The `xattr -c` command removes the quarantine flag from the `scan` binary so it can run without Gatekeeper blocking it.

### Build from source

```bash
git clone https://github.com/carlosacchi/osx-virus-scan.git
cd osx-virus-scan
swift build -c release
cp .build/release/scan /usr/local/bin/scan
```

## Usage

```bash
# Scan a file (positional argument)
scan /path/to/file.dmg

# Scan a file (explicit flag)
scan file -f /path/to/file.dmg

# JSON output
scan --json ~/Downloads/installer.pkg

# Verbose logging
scan --verbose ~/Downloads/app.zip

# Debug logging (includes verbose)
scan --debug ~/Downloads/suspicious.app
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | off | Output results as JSON |
| `--verbose` | off | Enable verbose logging to stderr |
| `--debug` | off | Enable debug logging (implies verbose) |
| `--strict` | off | Fail immediately if any analyzer errors |
| `--offline` / `--no-offline` | on | Force offline mode (no network calls) |
| `--reputation` | off | Enable hash reputation lookup via MalwareBazaar + VirusTotal (requires network) |
| `--cleanup` / `--no-cleanup` | on | Cleanup temporary files after scan |
| `--max-executable-checks` | 0 (unlimited) | Maximum executables to analyze in containers |
| `--hardened` | off | Enable hardened security checks (strict + reputation + verbose + no-offline) |

## Subcommands

### `scan <path>` / `scan file -f <path>`

Scan a single file. This is the default subcommand.

### `scan setup`

Install optional dependencies (ClamAV + YARA) via Homebrew and initialize databases. One command to get everything ready:

```bash
scan setup             # Install ClamAV + YARA + download virus definitions
scan setup --clamav    # Install ClamAV only
scan setup --yara      # Install YARA only
```

Requires [Homebrew](https://brew.sh). Already-installed tools are skipped.

### `scan update`

Update optional detection databases.

```bash
scan update            # Update all (ClamAV + YARA)
scan update --clamav   # Update ClamAV only
scan update --yara     # Update YARA rules only
```

Requires `brew install clamav` and/or `brew install yara`.

### `scan config`

Configure scan settings (e.g., API keys).

```bash
scan config virustotal-key YOUR_API_KEY
```

Configuration is stored in `~/.config/scan/config.json` with restrictive permissions (0600).

## Supported File Types

| Type | Detection | What happens |
|------|-----------|-------------|
| **DMG** | Extension + magic bytes | Mounted read-only, contents scanned, auto-unmounted |
| **ZIP** | Magic bytes (`PK`) | Extracted to temp dir with Zip Slip protection |
| **PKG** | Magic bytes (`xar!`) | Expanded via `pkgutil`, installer scripts analyzed |
| **App bundle** | `.app` + `Contents/MacOS` | Code signing, Gatekeeper, entitlements checked |
| **Mach-O** | Magic bytes (`FEEDFACE`/`CAFEBABE`) | Architecture, linked libraries, load commands |
| **Script** | Shebang (`#!`) | Identified, no execution |

## Analyzers

| Analyzer | What it checks |
|----------|---------------|
| **CodeSign** | Signature validity via Security.framework, team ID, ad-hoc detection |
| **Gatekeeper** | `spctl --assess` acceptance/rejection |
| **Entitlements** | Dangerous entitlements (disable-library-validation, get-task-allow, etc.) |
| **MachO** | Architecture, linked dylibs, non-system library paths |
| **Persistence** | LaunchAgents/Daemons, login items, shell profile modifications |
| **Script** | Malicious patterns in scripts (network, privilege escalation, obfuscation, etc.) |
| **ClamAV** | Optional virus scan via `clamscan` (requires `brew install clamav`) |
| **YARA** | Optional rule matching (requires `brew install yara` + rules) |
| **Reputation** | Opt-in SHA-256 lookup against MalwareBazaar + VirusTotal APIs |

## Scoring

Findings are weighted by severity and summed into a 0-100 score:

| Severity | Weight | Verdict thresholds |
|----------|--------|--------------------|
| Info | 0 | 0 = Info |
| Low | 5 | 1-10 = Low |
| Medium | 15 | 11-30 = Medium |
| High | 30 | 31+ = High |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Info or Low verdict |
| 1 | Medium or High verdict |
| 2 | Scan error |
| 3 | Invalid arguments |

## Example Output

```
scan v0.9.0 — Static File Analyzer for macOS

File:       /System/Applications/Calculator.app
Type:       App Bundle
Size:       6.3 MB
SHA-256:    abc123...
Permissions: rwxr-xr-x
Quarantine: (none)

Verdict:    Low
Score:      5/100

Findings (5):
  [Info] Code signature is valid
    Signed by: com.apple.calculator (Team: not set)
  [Info] Gatekeeper accepted
    Assessment: accepted (Apple System)
  [Low] No hardened runtime
    Binary does not have hardened runtime flag enabled
    Remediation: Enable hardened runtime in Xcode build settings
  ...
```

## JSON Output

Use `--json` for machine-readable output:

```bash
scan --json /bin/ls | jq '.verdict'
```

The JSON schema includes: `tool`, `timestamp`, `input`, `verdict`, `score`, `metadata`, `manifest`, `findings`, `errors`, `scanDuration`.

## Optional Dependencies

These are **not required** but enable additional analyzers:

```bash
brew install clamav    # ClamAV virus scanning
brew install yara      # YARA rule matching
```

After installing ClamAV, initialize the database:

```bash
freshclam
```

YARA rules can be placed in `~/.config/scan/rules/yara/`.

## Architecture

```
Pipeline: ingest -> unpack/mount -> analyze -> score -> output
```

- **Ingest**: path normalization, file type detection, SHA-256 hash, quarantine attribute
- **Unpack**: DMG mount, ZIP extract, PKG expand (with Zip Slip / symlink escape protection)
- **Analyze**: 9 analyzers run in parallel, each producing typed findings
- **Score**: weighted aggregation of findings into verdict
- **Output**: human-readable text or JSON

Built with Swift 6 using `async/await`, Security.framework for code signing, and CryptoKit for hashing. Single external dependency: [swift-argument-parser](https://github.com/apple/swift-argument-parser).

## Production Ready (v1.0.0)

All core security features implemented and tested:

- ✅ **ScriptAnalyzer** - Comprehensive script malware detection with 50+ patterns
- ✅ **Unlimited executable analysis** - Configurable limit with `--max-executable-checks`
- ✅ **Tightened verdict logic** - High severity findings force High verdict
- ✅ **Robust file-type detection** - Magic byte detection for DMG/ZIP/PKG/Mach-O
- ✅ **Expanded YARA baseline** - 11 curated malware detection rules
- ✅ **Multi-source reputation** - MalwareBazaar + VirusTotal integration
- ✅ **Anti-evasion test suite** - 79 tests including bypass scenarios
- ✅ **Coverage transparency** - Detailed reporting of analyzers and findings
- ✅ **Hardened mode** - Preset for maximum security checking

## Roadmap

### Current Status

`scan` is a useful static triage tool, but **not sufficient as a standalone safety gate for torrent apps** or high-risk downloads. It works well as a first-pass analyzer but lacks the depth for high-confidence malware detection in adversarial scenarios.

**Rating:**
- Engineering quality: 7/10
- Malware detection sufficiency: 4/10

### Known Limitations & Future Work

Findings are ordered by severity and include source file references for tracking.

#### Critical Priority

1. **No analyzer for standalone scripts** — Malicious shell/Python/Perl scripts outside of PKG installers pass clean.
   *Affected:* [AnalyzerRegistry.swift:10](Sources/scan/Analyzers/AnalyzerRegistry.swift#L10), [InstallerScriptAnalyzer.swift:47](Sources/scan/Analyzers/InstallerScriptAnalyzer.swift#L47)

2. **Script heuristics restricted to PKG only** — ZIP/DMG payloads containing scripts are not analyzed for malicious patterns.
   *Affected:* [InstallerScriptAnalyzer.swift:49](Sources/scan/Analyzers/InstallerScriptAnalyzer.swift#L49)

#### High Priority

3. **Incomplete inner executable coverage** — Only first 20 executables in large bundles are checked (`prefix(20)`), allowing malicious binaries to hide.
   *Affected:* [CodeSignAnalyzer.swift:26](Sources/scan/Analyzers/CodeSignAnalyzer.swift#L26)

4. **Inconsistent deep analysis** — Entitlements and Mach-O checks focus on root files, not all inner executables in extracted archives.
   *Affected:* [EntitlementsAnalyzer.swift:42](Sources/scan/Analyzers/EntitlementsAnalyzer.swift#L42), [MachOAnalyzer.swift:16](Sources/scan/Analyzers/MachOAnalyzer.swift#L16)

5. **Weak DMG detection** — Relies on `.dmg` extension fallback instead of robust magic byte detection, easily evaded by renaming.
   *Affected:* [FileTypeDetector.swift:107](Sources/scan/Ingest/FileTypeDetector.swift#L107)

6. **Scoring understates severe indicators** — A single High finding can still result in Medium verdict (score 30).
   *Affected:* [ScoringConfig.swift:23](Sources/scan/Scoring/ScoringConfig.swift#L23), [ScoringEngineTests.swift:41](Tests/scanTests/Scoring/ScoringEngineTests.swift#L41)

#### Medium Priority

7. **Weak safe defaults** — Offline mode enabled by default, reputation checking requires explicit opt-in.
   *Affected:* [ScanFileCommand.swift:28](Sources/scan/Commands/ScanFileCommand.swift#L28), [ScanFileCommand.swift:31](Sources/scan/Commands/ScanFileCommand.swift#L31), [ReputationAnalyzer.swift:7](Sources/scan/Analyzers/ReputationAnalyzer.swift#L7)

8. **Narrow YARA baseline** — Only two pinned rules in updater, limiting detection coverage.
   *Affected:* [UpdateCommand.swift:86](Sources/scan/Commands/UpdateCommand.swift#L86)

9. **Gatekeeper failures downgraded to Info** — `gatekeeper_unavailable` reduces risk signal quality.
   *Affected:* [GatekeeperAnalyzer.swift:85](Sources/scan/Analyzers/GatekeeperAnalyzer.swift#L85)

#### Low Priority / Maintainability

10. **Pipeline.run complexity** — Centralized orchestration in one long method makes testing and evolution harder.
    *Affected:* [Pipeline.swift:15](Sources/scan/Core/Pipeline.swift#L15)

11. **VirusTotal expectation drift** — Docs mention VirusTotal support, but runtime only queries MalwareBazaar.
    *Affected:* [Config.swift:5](Sources/scan/Core/Config.swift#L5), [README.md:132](#L132), [ReputationAnalyzer.swift:17](Sources/scan/Analyzers/ReputationAnalyzer.swift#L17)

12. **Inconsistent versioning** — Version numbers drift across docs, examples, and runtime outputs.
    *Affected:* [README.md:157](#L157), [ScanResult.swift:8](Sources/scan/Models/ScanResult.swift#L8)

### What's Good

- **Clean domain separation** — Ingest, Unpack, Analyzers, Scoring, Output are well-organized.
  *See:* [Analyzer.swift:17](Sources/scan/Analyzers/Analyzer.swift#L17)

- **Solid async orchestration** — Analyzer registry uses task groups with deterministic ordering.
  *See:* [AnalyzerRegistry.swift:42](Sources/scan/Analyzers/AnalyzerRegistry.swift#L42)

- **Security-minded unpacking** — Zip bomb heuristics, escape validation, symlink handling are all present.
  *See:* [ZIPExtractor.swift](Sources/scan/Unpack/ZIPExtractor.swift)

### Architecture Verdict

The v1.0 architecture is solid for a static scanner, but **threat-model coverage is not yet strong enough for high-stakes malware decisions** (e.g., torrent apps, untrusted downloads). It works well as a triage layer in a defense-in-depth strategy.

## License

MIT
