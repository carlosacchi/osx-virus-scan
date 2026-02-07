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
# Download the latest release
curl -LO https://github.com/carlosacchi/osx-virus-scan/releases/latest/download/scan-macos.zip
unzip scan-macos.zip

# Remove macOS quarantine attribute and make executable
xattr -c scan && chmod +x scan

# Move to PATH
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
| `--reputation` | off | Enable hash reputation lookup via MalwareBazaar (requires network) |
| `--cleanup` / `--no-cleanup` | on | Cleanup temporary files after scan |

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
| **InstallerScript** | Suspicious patterns in preinstall/postinstall (curl, chmod 777, eval, base64, etc.) |
| **ClamAV** | Optional virus scan via `clamscan` (requires `brew install clamav`) |
| **YARA** | Optional rule matching (requires `brew install yara` + rules) |
| **Reputation** | Opt-in SHA-256 lookup against MalwareBazaar API |

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
scan v0.8.0 — Static File Analyzer for macOS

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

## License

MIT
