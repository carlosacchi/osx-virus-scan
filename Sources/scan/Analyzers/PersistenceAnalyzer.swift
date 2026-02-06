import Foundation

/// Detects persistence mechanisms in container contents (LaunchAgents, LaunchDaemons, etc.)
struct PersistenceAnalyzer: Analyzer, Sendable {
    let name = "persistence"

    /// Patterns indicating persistence mechanisms
    private static let persistencePatterns: [(pattern: String, severity: Verdict, description: String)] = [
        ("Library/LaunchAgents/", .high, "User-level launch agent"),
        ("Library/LaunchDaemons/", .high, "System-level launch daemon"),
        ("Library/StartupItems/", .high, "Legacy startup item"),
        ("Library/Application Support/", .info, "Application support directory"),
        ("LoginItems/", .medium, "Login item"),
        (".mobileconfig", .high, "Configuration profile"),
    ]

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // Only analyze containers with manifests (DMG, ZIP, PKG contents)
        return context.manifest != nil
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        guard let manifest = context.manifest, let contentRoot = context.contentRoot else {
            return findings
        }

        // Check manifest entries for persistence-related paths
        for entry in manifest.entries {
            for (pattern, severity, description) in Self.persistencePatterns {
                if entry.relativePath.contains(pattern) {
                    findings.append(Finding(
                        id: "persistence_\(pattern.replacingOccurrences(of: "/", with: "_").lowercased())",
                        category: .persistence,
                        severity: severity,
                        confidence: .high,
                        summary: "Contains \(description): \(entry.relativePath)",
                        evidence: "File found at: \(entry.relativePath) (size: \(entry.size) bytes)",
                        location: entry.relativePath,
                        remediation: severity >= .medium
                            ? "Review the contents of this file to verify it is expected."
                            : nil
                    ))

                    // If it's a plist in a LaunchAgents/Daemons path, inspect it
                    if (pattern.contains("LaunchAgents") || pattern.contains("LaunchDaemons"))
                        && entry.relativePath.hasSuffix(".plist") {
                        let plistURL = contentRoot.appendingPathComponent(entry.relativePath)
                        let plistFindings = analyzeLaunchPlist(at: plistURL, relativePath: entry.relativePath)
                        findings.append(contentsOf: plistFindings)
                    }
                }
            }
        }

        // Check for shell profile modifications
        let shellProfiles = [".bash_profile", ".bashrc", ".zshrc", ".zprofile", ".profile"]
        for entry in manifest.entries {
            let filename = (entry.relativePath as NSString).lastPathComponent
            if shellProfiles.contains(filename) {
                findings.append(Finding(
                    id: "persistence_shell_profile",
                    category: .persistence,
                    severity: .high,
                    confidence: .medium,
                    summary: "Contains shell profile modification: \(filename)",
                    evidence: "File found at: \(entry.relativePath)",
                    location: entry.relativePath,
                    remediation: "Modifying shell profiles is a persistence mechanism. Review the file contents."
                ))
            }
        }

        return findings
    }

    // MARK: - LaunchAgent/Daemon plist analysis

    private func analyzeLaunchPlist(at url: URL, relativePath: String) -> [Finding] {
        var findings: [Finding] = []

        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else {
            return findings
        }

        // Check RunAtLoad
        if plist["RunAtLoad"] as? Bool == true {
            findings.append(Finding(
                id: "persistence_run_at_load",
                category: .persistence,
                severity: .high,
                confidence: .high,
                summary: "Launch agent/daemon runs at load",
                evidence: "RunAtLoad: true in \(relativePath)",
                location: relativePath,
                remediation: "This service will start automatically. Verify the ProgramArguments point to a trusted executable."
            ))
        }

        // Check KeepAlive
        if plist["KeepAlive"] as? Bool == true {
            findings.append(Finding(
                id: "persistence_keep_alive",
                category: .persistence,
                severity: .medium,
                confidence: .high,
                summary: "Launch agent/daemon has KeepAlive enabled",
                evidence: "KeepAlive: true in \(relativePath)",
                location: relativePath,
                remediation: "The system will restart this service if it exits."
            ))
        }

        // Extract and log ProgramArguments
        if let programArgs = plist["ProgramArguments"] as? [String] {
            let argsStr = programArgs.joined(separator: " ")
            findings.append(Finding(
                id: "persistence_program_args",
                category: .persistence,
                severity: .info,
                confidence: .high,
                summary: "Launch service program: \(programArgs.first ?? "unknown")",
                evidence: "ProgramArguments: \(argsStr)",
                location: relativePath,
                remediation: nil
            ))
        }

        return findings
    }
}
