import Foundation

/// Optional YARA rules engine — requires yara to be installed (brew install yara)
struct YaraAnalyzer: Analyzer, Sendable {
    let name = "yara"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // YARA can scan any file type
        return true
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []
        let shell = ShellRunner()

        // Find yara binary
        let yaraPaths = ["/opt/homebrew/bin/yara", "/usr/local/bin/yara"]
        guard let yaraPath = yaraPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            findings.append(Finding(
                id: "yara_not_installed",
                category: .yara,
                severity: .info,
                confidence: .high,
                summary: "YARA not installed",
                evidence: "yara not found at /opt/homebrew/bin or /usr/local/bin",
                location: nil,
                remediation: "Install with: brew install yara"
            ))
            return findings
        }

        // Check for rules
        let rulesDir = ScanConfig.yaraRulesDir
        let customRulesDir = ScanConfig.yaraCustomRulesDir

        let allRuleDirs = [rulesDir, customRulesDir]
        var ruleFiles: [URL] = []

        for dir in allRuleDirs {
            if let files = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: nil
            ) {
                ruleFiles.append(contentsOf: files.filter {
                    $0.pathExtension == "yar" || $0.pathExtension == "yara"
                })
            }
        }

        if ruleFiles.isEmpty {
            findings.append(Finding(
                id: "yara_no_rules",
                category: .yara,
                severity: .info,
                confidence: .high,
                summary: "No YARA rules found",
                evidence: "No .yar/.yara files in \(rulesDir.path) or \(customRulesDir.path)",
                location: nil,
                remediation: "Add YARA rules to \(rulesDir.path) or run 'scan update' to download rules."
            ))
            return findings
        }

        context.logger.info("Using \(ruleFiles.count) YARA rule file(s)")

        // Determine scan target
        let scanTarget: String
        if let contentRoot = context.contentRoot {
            scanTarget = contentRoot.path
        } else {
            scanTarget = context.fileURL.path
        }

        // Run yara with each rule file
        for ruleFile in ruleFiles {
            let result = try await shell.run(
                executable: yaraPath,
                arguments: ["-r", ruleFile.path, scanTarget],
                timeout: 120
            )

            if result.exitCode == 0 && !result.stdout.isEmpty {
                // Parse YARA matches
                let lines = result.stdout.components(separatedBy: "\n").filter { !$0.isEmpty }
                for line in lines {
                    // Format: RuleName /path/to/matched/file
                    let parts = line.components(separatedBy: " ")
                    let ruleName = parts.first ?? "unknown"
                    let matchedFile = parts.count > 1 ? parts.dropFirst().joined(separator: " ") : ""

                    findings.append(Finding(
                        id: "yara_match_\(ruleName.lowercased())",
                        category: .yara,
                        severity: .high,
                        confidence: .medium,
                        summary: "YARA rule match: \(ruleName)",
                        evidence: "Rule '\(ruleName)' matched in \(matchedFile)",
                        location: matchedFile,
                        remediation: "Review the YARA rule and the matched file for potential threats."
                    ))
                }
            }
        }

        if findings.isEmpty || findings.allSatisfy({ $0.id == "yara_no_rules" || $0.id == "yara_not_installed" }) {
            findings.append(Finding(
                id: "yara_clean",
                category: .yara,
                severity: .info,
                confidence: .medium,
                summary: "YARA: no rule matches",
                evidence: "Scanned with \(ruleFiles.count) rule file(s), no matches",
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }
}
