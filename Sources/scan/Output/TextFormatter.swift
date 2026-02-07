import Foundation

/// Formats scan results as human-readable terminal output
struct TextFormatter: OutputFormatter, Sendable {

    func format(_ result: ScanResult) -> String {
        var lines: [String] = []

        // Header
        lines.append("scan v\(result.tool.version) — Static File Analyzer for macOS")
        lines.append("")

        // File info
        lines.append("File:       \(result.metadata.path)")
        if result.metadata.isSymlink {
            lines.append("Resolved:   \(result.metadata.resolvedPath)")
        }
        lines.append("Type:       \(result.metadata.fileType.displayName)")
        lines.append("Size:       \(result.metadata.formattedSize)")
        lines.append("SHA-256:    \(result.metadata.sha256)")
        lines.append("Permissions: \(result.metadata.permissions)")

        // Quarantine
        if let q = result.metadata.quarantine {
            var quarantineParts: [String] = []
            if let agent = q.agentName {
                quarantineParts.append("by \(agent)")
            }
            if let url = q.originURL {
                quarantineParts.append("from \(url)")
            }
            if let ts = q.timestamp {
                let fmt = DateFormatter()
                fmt.dateStyle = .medium
                fmt.timeStyle = .short
                quarantineParts.append("on \(fmt.string(from: ts))")
            }
            let detail = quarantineParts.isEmpty ? q.rawValue : quarantineParts.joined(separator: " ")
            lines.append("Quarantine: Downloaded \(detail)")
        } else {
            lines.append("Quarantine: (none)")
        }

        lines.append("")

        // Verdict
        let verdictColor = colorForVerdict(result.verdict)
        lines.append("Verdict:    \(verdictColor)\(result.verdict.rawValue)\(resetColor)")
        lines.append("Score:      \(result.score)/100")

        // Manifest (container contents)
        if let manifest = result.manifest {
            lines.append("")
            let sizeFormatter = ByteCountFormatter()
            sizeFormatter.countStyle = .file
            lines.append("Contents:   \(manifest.totalFiles) files, \(sizeFormatter.string(fromByteCount: Int64(manifest.totalSize)))")
            let executables = manifest.entries.filter { $0.isExecutable }
            if !executables.isEmpty {
                lines.append("Executables: \(executables.count)")
                for exe in executables.prefix(10) {
                    let hash = exe.sha256.map { " [\(String($0.prefix(12)))...]" } ?? ""
                    lines.append("  \(exe.relativePath)\(hash)")
                }
                if executables.count > 10 {
                    lines.append("  ... and \(executables.count - 10) more")
                }
            }
        }

        lines.append("")

        // Findings
        if result.findings.isEmpty {
            lines.append("Findings:   (none)")
        } else {
            lines.append("Findings (\(result.findings.count)):")
            for finding in result.findings {
                let sevColor = colorForVerdict(finding.severity)
                lines.append("  [\(sevColor)\(finding.severity.rawValue)\(resetColor)] \(finding.summary)")
                lines.append("    \(finding.evidence)")
                if let location = finding.location {
                    lines.append("    Location: \(location)")
                }
                if let remediation = finding.remediation {
                    lines.append("    Remediation: \(remediation)")
                }
            }
        }

        // Errors
        if !result.errors.isEmpty {
            lines.append("")
            lines.append("Errors (\(result.errors.count)):")
            for err in result.errors {
                lines.append("  [\(err.step)] \(err.message)")
            }
        }

        // Coverage Summary
        lines.append("")
        lines.append("Coverage:")
        lines.append("  Analyzers:  \(result.coverage.applicableAnalyzers)/\(result.coverage.totalAnalyzers) applicable (\(result.coverage.analyzersRun.joined(separator: ", ")))")
        lines.append("  Categories: \(result.coverage.categoriesCovered.joined(separator: ", "))")

        let severities = ["high", "medium", "low", "info"]
        let severityCounts = severities.compactMap { sev in
            guard let count = result.coverage.findingsBySeverity[sev], count > 0 else { return nil }
            return "\(count) \(sev.capitalized)"
        }.joined(separator: ", ")
        lines.append("  Findings:   \(severityCounts.isEmpty ? "none" : severityCounts)")
        lines.append("  Duration:   \(String(format: "%.1f", result.coverage.executionTime))s")

        return lines.joined(separator: "\n")
    }

    // ANSI color codes — disabled when stdout is not a TTY (e.g., piped to file)
    private static let isTTY = isatty(STDOUT_FILENO) != 0

    private var resetColor: String { Self.isTTY ? "\u{001B}[0m" : "" }

    private func colorForVerdict(_ verdict: Verdict) -> String {
        guard Self.isTTY else { return "" }
        switch verdict {
        case .info: return "\u{001B}[36m"    // cyan
        case .low: return "\u{001B}[32m"     // green
        case .medium: return "\u{001B}[33m"  // yellow
        case .high: return "\u{001B}[31m"    // red
        case .unknown: return "\u{001B}[35m" // magenta
        case .error: return "\u{001B}[31m"   // red
        }
    }
}
