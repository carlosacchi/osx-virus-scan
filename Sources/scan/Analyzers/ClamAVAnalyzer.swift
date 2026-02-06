import Foundation

/// Optional ClamAV integration — requires clamscan to be installed (brew install clamav)
struct ClamAVAnalyzer: Analyzer, Sendable {
    let name = "clamav"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // ClamAV can scan any file type
        return true
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []
        let shell = ShellRunner()

        // Find clamscan binary
        let clamPaths = ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"]
        guard let clamPath = clamPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            findings.append(Finding(
                id: "clamav_not_installed",
                category: .signatureDB,
                severity: .info,
                confidence: .high,
                summary: "ClamAV not installed",
                evidence: "clamscan not found at /opt/homebrew/bin or /usr/local/bin",
                location: nil,
                remediation: "Install with: brew install clamav && freshclam"
            ))
            return findings
        }

        context.logger.info("Using ClamAV at: \(clamPath)")

        // Determine scan target
        let scanTarget: String
        if let contentRoot = context.contentRoot {
            // Scan extracted contents for containers
            scanTarget = contentRoot.path
        } else {
            scanTarget = context.fileURL.path
        }

        // Run clamscan
        let result = try await shell.run(
            executable: clamPath,
            arguments: [
                "--no-summary",
                "--infected",
                "--recursive",
                scanTarget
            ],
            timeout: 300 // 5 minutes for large scans
        )

        switch result.exitCode {
        case 0:
            // Clean
            findings.append(Finding(
                id: "clamav_clean",
                category: .signatureDB,
                severity: .info,
                confidence: .high,
                summary: "ClamAV: no threats detected",
                evidence: "clamscan found no infected files",
                location: nil,
                remediation: nil
            ))

        case 1:
            // Virus found — parse output
            let lines = result.stdout.components(separatedBy: "\n").filter { $0.contains("FOUND") }
            for line in lines {
                // Format: /path/to/file: ThreatName FOUND
                let parts = line.components(separatedBy: ": ")
                let threatInfo = parts.count > 1
                    ? parts[1].replacingOccurrences(of: " FOUND", with: "")
                    : "Unknown threat"
                let filePath = parts.first ?? ""

                findings.append(Finding(
                    id: "clamav_detection",
                    category: .signatureDB,
                    severity: .high,
                    confidence: .high,
                    summary: "ClamAV detection: \(threatInfo)",
                    evidence: "Detected in: \(filePath)",
                    location: filePath,
                    remediation: "This file matches a known malware signature. Do not execute it."
                ))
            }

        case 2:
            // Error
            findings.append(Finding(
                id: "clamav_error",
                category: .signatureDB,
                severity: .info,
                confidence: .low,
                summary: "ClamAV scan encountered an error",
                evidence: result.stderr.trimmingCharacters(in: .whitespacesAndNewlines),
                location: nil,
                remediation: "Run 'freshclam' to update virus definitions, then retry."
            ))

        default:
            break
        }

        return findings
    }
}
