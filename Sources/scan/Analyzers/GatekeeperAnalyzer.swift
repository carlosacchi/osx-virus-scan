import Foundation

/// Checks Gatekeeper assessment via spctl
struct GatekeeperAnalyzer: Analyzer, Sendable {
    let name = "gatekeeper"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        let analyzableTypes: [FileType] = [.machO, .app, .dmg, .pkg]
        return analyzableTypes.contains(context.metadata.fileType)
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []
        let shell = ShellRunner()

        // Determine assessment type
        let assessType: String
        switch context.metadata.fileType {
        case .pkg:
            assessType = "install"
        case .app, .machO:
            assessType = "execute"
        default:
            assessType = "open"
        }

        context.logger.debug("spctl --assess --type \(assessType) \(context.fileURL.path)")

        let result = try await shell.run(
            executable: "/usr/sbin/spctl",
            arguments: ["--assess", "--type", assessType, "--verbose", context.fileURL.path],
            timeout: 30
        )

        // Combine stdout and stderr (spctl outputs to stderr)
        let output = (result.stdout + result.stderr).trimmingCharacters(in: .whitespacesAndNewlines)

        if result.exitCode == 0 {
            // Accepted
            findings.append(Finding(
                id: "gatekeeper_accepted",
                category: .notarization,
                severity: .info,
                confidence: .high,
                summary: "Gatekeeper assessment: accepted",
                evidence: output.isEmpty ? "spctl --assess passed" : output,
                location: nil,
                remediation: nil
            ))

            // Check if it mentions notarization
            if output.lowercased().contains("notarized") {
                findings.append(Finding(
                    id: "gatekeeper_notarized",
                    category: .notarization,
                    severity: .info,
                    confidence: .high,
                    summary: "File is notarized by Apple",
                    evidence: output,
                    location: nil,
                    remediation: nil
                ))
            }
        } else if result.exitCode == 3 {
            // Rejected — but check if it's just a "not an app" rejection for standalone binaries
            let isNotAnApp = output.contains("does not seem to be an app")
            let severity: Verdict = isNotAnApp ? .info : .high
            let confidence: Confidence = isNotAnApp ? .medium : .high

            findings.append(Finding(
                id: isNotAnApp ? "gatekeeper_not_app" : "gatekeeper_rejected",
                category: .notarization,
                severity: severity,
                confidence: confidence,
                summary: isNotAnApp
                    ? "Gatekeeper: not assessed (standalone binary, not an app bundle)"
                    : "Gatekeeper assessment: rejected",
                evidence: output.isEmpty ? "spctl --assess rejected the file" : output,
                location: nil,
                remediation: isNotAnApp
                    ? nil
                    : "This file would be blocked by Gatekeeper. macOS may show a warning or refuse to open it."
            ))
        } else {
            // Assessment error or not available
            findings.append(Finding(
                id: "gatekeeper_unavailable",
                category: .notarization,
                severity: .info,
                confidence: .low,
                summary: "Gatekeeper assessment not available",
                evidence: "spctl exited with code \(result.exitCode): \(output)",
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }
}
