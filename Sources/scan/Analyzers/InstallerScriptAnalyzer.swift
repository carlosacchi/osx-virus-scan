import Foundation

/// Analyzes installer scripts (preinstall/postinstall) for suspicious patterns
struct InstallerScriptAnalyzer: Analyzer, Sendable {
    let name = "installer-scripts"

    /// Suspicious patterns with severity and description
    private static let suspiciousPatterns: [(pattern: String, severity: Verdict, reason: String)] = [
        // Network activity
        ("curl ", .high, "Network download in installer script"),
        ("wget ", .high, "Network download in installer script"),
        ("/dev/tcp/", .high, "Bash TCP connection"),
        ("nc -", .high, "Netcat usage"),
        ("ncat ", .high, "Netcat usage"),

        // Privilege escalation / system modification
        ("chmod 777", .high, "Setting world-writable permissions"),
        ("chmod +s", .high, "Setting SUID bit"),
        ("chmod u+s", .high, "Setting SUID bit"),
        ("rm -rf /", .high, "Dangerous recursive deletion at root"),
        ("dscl ", .high, "Directory service command (user/group manipulation)"),
        ("spctl --master-disable", .high, "Disabling Gatekeeper"),
        ("csrutil ", .high, "SIP-related command"),

        // Code execution / obfuscation
        ("eval ", .medium, "Dynamic code evaluation"),
        ("base64 ", .medium, "Base64 encoding/decoding (potential obfuscation)"),
        ("openssl enc", .medium, "OpenSSL encryption/decryption"),
        ("python -c", .medium, "Inline Python execution"),
        ("python3 -c", .medium, "Inline Python execution"),
        ("ruby -e", .medium, "Inline Ruby execution"),
        ("perl -e", .medium, "Inline Perl execution"),
        ("osascript", .medium, "AppleScript execution"),

        // Persistence
        ("launchctl load", .high, "Loading launch agent/daemon"),
        ("launchctl bootstrap", .high, "Bootstrapping launch service"),
        ("defaults write", .medium, "Modifying macOS defaults"),

        // Suspicious patterns
        ("xattr -d com.apple.quarantine", .medium, "Removing quarantine attribute"),
        ("kextload", .high, "Loading kernel extension"),
        ("killall", .medium, "Killing processes"),
        ("pkill", .medium, "Killing processes"),
    ]

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // Analyze PKG contents or any container with scripts
        return context.manifest != nil && context.metadata.fileType == .pkg
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        guard let manifest = context.manifest, let contentRoot = context.contentRoot else {
            return findings
        }

        // Find installer scripts
        let scriptNames = Set(["preinstall", "postinstall", "preflight", "postflight"])

        for entry in manifest.entries {
            let filename = (entry.relativePath as NSString).lastPathComponent.lowercased()

            let isScript = scriptNames.contains(filename)
                || filename.hasPrefix("preinstall")
                || filename.hasPrefix("postinstall")

            guard isScript else { continue }

            let scriptURL = contentRoot.appendingPathComponent(entry.relativePath)

            // Try to read as text
            guard let content = try? String(contentsOf: scriptURL, encoding: .utf8) else {
                // Binary script — flag it
                findings.append(Finding(
                    id: "installer_script_binary",
                    category: .packaging,
                    severity: .medium,
                    confidence: .medium,
                    summary: "Installer script is a binary, not a text script",
                    evidence: "Cannot read \(entry.relativePath) as text",
                    location: entry.relativePath,
                    remediation: "Binary installer scripts are unusual and harder to audit."
                ))
                continue
            }

            // Scan for suspicious patterns
            for (pattern, severity, reason) in Self.suspiciousPatterns {
                if content.contains(pattern) {
                    findings.append(Finding(
                        id: "installer_script_\(pattern.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "_").lowercased())",
                        category: .heuristic,
                        severity: severity,
                        confidence: .medium,
                        summary: "\(reason)",
                        evidence: "Found '\(pattern)' in \(entry.relativePath)",
                        location: entry.relativePath,
                        remediation: "Review the installer script to confirm this operation is expected."
                    ))
                }
            }

            // Check script length (very long scripts are suspicious)
            let lineCount = content.components(separatedBy: "\n").count
            if lineCount > 200 {
                findings.append(Finding(
                    id: "installer_script_long",
                    category: .heuristic,
                    severity: .low,
                    confidence: .low,
                    summary: "Installer script is unusually long (\(lineCount) lines)",
                    evidence: "\(entry.relativePath) has \(lineCount) lines",
                    location: entry.relativePath,
                    remediation: "Long installer scripts may contain obfuscated or unexpected operations."
                ))
            }
        }

        return findings
    }
}
