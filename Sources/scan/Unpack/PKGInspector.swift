import Foundation

/// Inspects PKG files without installing them
final class PKGInspector: Unpacker, @unchecked Sendable {
    let supportedTypes: [FileType] = [.pkg]

    private let shell = ShellRunner()
    private let logger: VerboseLogger
    private var expandedDir: URL?

    init(logger: VerboseLogger) {
        self.logger = logger
    }

    func unpack(source: URL, into destination: URL) async throws -> UnpackResult {
        var findings: [Finding] = []

        logger.info("Inspecting PKG: \(source.lastPathComponent)")

        let expandDir = destination.appendingPathComponent("pkg-expand")
        try FileManager.default.createDirectory(at: expandDir, withIntermediateDirectories: true)
        expandedDir = expandDir

        // Try pkgutil --expand-full first (extracts payload and scripts)
        let result = try await shell.run(
            executable: "/usr/sbin/pkgutil",
            arguments: ["--expand-full", source.path, expandDir.path],
            timeout: 120
        )

        if !result.succeeded {
            // Fallback: try pkgutil --expand (doesn't extract payload fully)
            logger.info("pkgutil --expand-full failed, trying --expand")

            // Clean and retry
            try? FileManager.default.removeItem(at: expandDir)
            try FileManager.default.createDirectory(at: expandDir, withIntermediateDirectories: true)

            let fallbackResult = try await shell.run(
                executable: "/usr/sbin/pkgutil",
                arguments: ["--expand", source.path, expandDir.path],
                timeout: 120
            )

            if !fallbackResult.succeeded {
                throw ScanError.unpackFailed(
                    type: .pkg,
                    reason: "pkgutil expand failed (exit \(fallbackResult.exitCode)): \(fallbackResult.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            }

            findings.append(Finding(
                id: "pkg_partial_expand",
                category: .packaging,
                severity: .info,
                confidence: .high,
                summary: "PKG payload not fully extracted (using fallback expand)",
                evidence: "pkgutil --expand-full failed; used --expand instead",
                location: nil,
                remediation: nil
            ))
        }

        // Check for installer scripts
        let scriptFindings = try await inspectScripts(in: expandDir)
        findings.append(contentsOf: scriptFindings)

        // Check PKG signature
        let sigFindings = try await checkSignature(source: source)
        findings.append(contentsOf: sigFindings)

        logger.info("PKG expanded to: \(expandDir.path)")

        return UnpackResult(
            contentRoot: expandDir,
            findings: findings
        )
    }

    func cleanup() async {
        expandedDir = nil
    }

    // MARK: - PKG-specific inspection

    /// Find and report installer scripts (preinstall, postinstall)
    private func inspectScripts(in expandDir: URL) async throws -> [Finding] {
        var findings: [Finding] = []

        guard let enumerator = FileManager.default.enumerator(
            at: expandDir,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: []
        ) else { return findings }

        let scriptNames = ["preinstall", "postinstall", "preflight", "postflight",
                           "preinstall_actions", "postinstall_actions"]

        while let fileURL = enumerator.nextObject() as? URL {
            let name = fileURL.lastPathComponent.lowercased()
            if scriptNames.contains(name) || name.hasPrefix("preinstall") || name.hasPrefix("postinstall") {
                findings.append(Finding(
                    id: "pkg_installer_script",
                    category: .packaging,
                    severity: .medium,
                    confidence: .high,
                    summary: "PKG contains installer script: \(fileURL.lastPathComponent)",
                    evidence: "Script at: \(fileURL.path.replacingOccurrences(of: expandDir.path, with: ""))",
                    location: fileURL.path.replacingOccurrences(of: expandDir.path, with: ""),
                    remediation: "Review the script contents before allowing installation"
                ))
            }
        }

        return findings
    }

    /// Check PKG signature using pkgutil
    private func checkSignature(source: URL) async throws -> [Finding] {
        var findings: [Finding] = []

        let result = try await shell.run(
            executable: "/usr/sbin/pkgutil",
            arguments: ["--check-signature", source.path],
            timeout: 30
        )

        if result.stdout.contains("unsigned") || result.exitCode != 0 {
            findings.append(Finding(
                id: "pkg_unsigned",
                category: .signature,
                severity: .medium,
                confidence: .high,
                summary: "PKG is not signed",
                evidence: result.stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                location: nil,
                remediation: "Unsigned packages bypass Gatekeeper checks. Verify the source."
            ))
        } else if result.stdout.contains("signed") {
            // Extract signer info
            findings.append(Finding(
                id: "pkg_signed",
                category: .signature,
                severity: .info,
                confidence: .high,
                summary: "PKG is signed",
                evidence: result.stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }
}
