import Foundation

/// Analyzes script files for suspicious patterns and behaviors
struct ScriptAnalyzer: Analyzer, Sendable {
    let name = "scripts"

    // MARK: - Pattern Definitions

    /// Network activity patterns (High severity)
    private static let networkPatterns: [(String, Verdict, String)] = [
        ("curl ", .high, "Network download in script"),
        ("wget ", .high, "Network download in script"),
        ("/dev/tcp/", .high, "Bash TCP connection"),
        ("nc -", .high, "Netcat usage"),
        ("ncat ", .high, "Netcat usage"),
        ("socat ", .high, "Socat usage"),
        ("ssh ", .medium, "SSH remote connection"),
        ("scp ", .medium, "Secure copy usage"),
    ]

    /// Privilege escalation patterns (High severity)
    private static let privilegePatterns: [(String, Verdict, String)] = [
        ("sudo ", .high, "Elevated privileges"),
        ("chmod 777", .high, "World-writable permissions"),
        ("chmod +s", .high, "SUID bit setting"),
        ("chmod u+s", .high, "SUID bit setting"),
        ("chown root", .high, "Root ownership change"),
        ("rm -rf /", .high, "Dangerous root deletion"),
        ("dscl ", .high, "Directory service manipulation"),
        ("spctl --master-disable", .high, "Gatekeeper disable"),
        ("csrutil ", .high, "SIP manipulation"),
        ("kextload", .high, "Kernel extension loading"),
    ]

    /// Code execution patterns (Medium-High severity)
    private static let executionPatterns: [(String, Verdict, String)] = [
        ("eval ", .medium, "Dynamic code evaluation"),
        ("exec ", .medium, "Shell replacement/execution"),
        ("sh -c", .medium, "Inline shell execution"),
        ("bash -c", .medium, "Inline shell execution"),
        ("zsh -c", .medium, "Inline shell execution"),
        ("| bash", .high, "Piped shell execution"),
        ("| sh", .high, "Piped shell execution"),
        ("| zsh", .high, "Piped shell execution"),
        ("python -c", .medium, "Inline Python execution"),
        ("python3 -c", .medium, "Inline Python execution"),
        ("ruby -e", .medium, "Inline Ruby execution"),
        ("perl -e", .medium, "Inline Perl execution"),
        ("osascript", .medium, "AppleScript execution"),
        ("awk 'BEGIN{", .medium, "Inline AWK code"),
    ]

    /// Persistence mechanism patterns (High-Medium severity)
    private static let persistencePatterns: [(String, Verdict, String)] = [
        ("launchctl load", .high, "Launch agent/daemon loading"),
        ("launchctl bootstrap", .high, "Launch service bootstrap"),
        ("crontab ", .medium, "Cron job modification"),
        ("defaults write", .medium, "macOS defaults modification"),
        (".bash_profile", .low, "Shell profile modification"),
        (".bashrc", .low, "Shell profile modification"),
        (".zshrc", .low, "Shell profile modification"),
        ("at ", .medium, "Scheduled task"),
        ("batch ", .medium, "Scheduled task"),
    ]

    /// Obfuscation patterns (Medium severity)
    private static let obfuscationPatterns: [(String, Verdict, String)] = [
        ("base64 -d", .medium, "Base64 decoding"),
        ("xxd -r", .medium, "Hex decoding"),
        ("openssl enc", .medium, "Encryption/decryption"),
    ]

    /// File manipulation patterns (Medium-Low severity)
    private static let filePatterns: [(String, Verdict, String)] = [
        ("xattr -d com.apple.quarantine", .medium, "Quarantine removal"),
        ("rm -rf", .medium, "Recursive deletion"),
        ("killall", .low, "Process termination"),
        ("pkill", .low, "Process termination"),
        ("dd if=", .medium, "Disk/device manipulation"),
        ("diskutil ", .medium, "Disk utility usage"),
    ]

    /// Combined pattern list for iteration
    private static let allPatterns = networkPatterns + privilegePatterns +
                                      executionPatterns + persistencePatterns +
                                      obfuscationPatterns + filePatterns

    // MARK: - Analyzer Protocol

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // Mode 1: Standalone script file
        if context.metadata.fileType == .script {
            return true
        }

        // Mode 2: Container manifest with scripts
        if let manifest = context.manifest {
            return manifest.entries.contains { $0.type == .script }
        }

        return false
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        // Mode 1: Analyze standalone script
        if context.metadata.fileType == .script {
            findings.append(contentsOf: analyzeScriptFile(
                url: context.fileURL,
                relativePath: nil
            ))
        }

        // Mode 2: Analyze scripts in manifest
        if let manifest = context.manifest, let contentRoot = context.contentRoot {
            for entry in manifest.entries where entry.type == .script && !entry.isSymlink {
                let scriptURL = contentRoot.appendingPathComponent(entry.relativePath)
                findings.append(contentsOf: analyzeScriptFile(
                    url: scriptURL,
                    relativePath: entry.relativePath
                ))
            }
        }

        return findings
    }

    // MARK: - Private Helpers

    /// Analyzes a single script file
    private func analyzeScriptFile(url: URL, relativePath: String?) -> [Finding] {
        var findings: [Finding] = []
        let location = relativePath

        // Check file size before reading
        if let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
           let fileSize = attrs[.size] as? Int64, fileSize > 10_000_000 {
            findings.append(Finding(
                id: "script_too_large",
                category: .heuristic,
                severity: .medium,
                confidence: .high,
                summary: "Script file is unusually large (\(ByteCountFormatter.string(fromByteCount: fileSize, countStyle: .file)))",
                evidence: "File size: \(fileSize) bytes",
                location: location,
                remediation: "Very large scripts may contain embedded data or obfuscated code."
            ))
            return findings
        }

        // Try to read as text
        guard let content = try? String(contentsOf: url, encoding: .utf8) else {
            findings.append(Finding(
                id: "script_binary",
                category: .heuristic,
                severity: .high,
                confidence: .high,
                summary: "Script is binary or uses non-UTF8 encoding",
                evidence: "Cannot read script as text",
                location: location,
                remediation: "Binary scripts are unusual and harder to audit."
            ))
            return findings
        }

        // Check for null bytes
        if content.contains("\0") {
            findings.append(Finding(
                id: "script_null_bytes",
                category: .heuristic,
                severity: .high,
                confidence: .high,
                summary: "Script contains null bytes",
                evidence: "Found null bytes in script content",
                location: location,
                remediation: "Scripts should not contain null bytes."
            ))
        }

        // Extract and analyze shebang
        if let shebang = extractShebang(from: content) {
            findings.append(contentsOf: analyzeShebang(shebang, location: location))
        } else {
            findings.append(Finding(
                id: "script_no_shebang",
                category: .heuristic,
                severity: .low,
                confidence: .medium,
                summary: "Script lacks shebang line",
                evidence: "No #! interpreter declaration found",
                location: location,
                remediation: "Scripts should specify interpreter with shebang (#!)."
            ))
        }

        // Scan for malicious patterns
        findings.append(contentsOf: scanForPatterns(content: content, location: location))

        // Detect obfuscation
        findings.append(contentsOf: detectObfuscation(content: content, location: location))

        // Check script length
        if let lengthFinding = checkScriptLength(content: content, location: location) {
            findings.append(lengthFinding)
        }

        return findings
    }

    /// Extracts shebang from script content
    private func extractShebang(from content: String) -> String? {
        guard content.hasPrefix("#!") else { return nil }
        let firstLine = content.components(separatedBy: "\n").first ?? ""
        return String(firstLine.dropFirst(2).trimmingCharacters(in: .whitespaces))
    }

    /// Analyzes shebang interpreter
    private func analyzeShebang(_ shebang: String, location: String?) -> [Finding] {
        var findings: [Finding] = []

        // Check for unusual interpreter locations
        let suspiciousLocations = ["/tmp/", "/var/tmp/", "/dev/shm/"]
        if suspiciousLocations.contains(where: { shebang.contains($0) }) {
            findings.append(Finding(
                id: "script_shebang_unusual_location",
                category: .heuristic,
                severity: .high,
                confidence: .high,
                summary: "Script uses interpreter from suspicious location",
                evidence: "Shebang: #!\(shebang)",
                location: location,
                remediation: "Interpreters should be in standard system paths."
            ))
        }

        // Detect unusual interpreters
        let interpreterPath = shebang.components(separatedBy: " ").first ?? ""
        let interpreter = (interpreterPath as NSString).lastPathComponent

        let knownInterpreters = ["bash", "sh", "zsh", "python", "python3", "ruby", "perl", "env"]
        if !knownInterpreters.contains(interpreter) {
            findings.append(Finding(
                id: "script_shebang_unusual",
                category: .heuristic,
                severity: .medium,
                confidence: .medium,
                summary: "Script uses unusual interpreter: \(interpreter)",
                evidence: "Shebang: #!\(shebang)",
                location: location,
                remediation: "Verify this interpreter is expected and trusted."
            ))
        }

        return findings
    }

    /// Scans for malicious patterns
    private func scanForPatterns(content: String, location: String?) -> [Finding] {
        var findings: [Finding] = []

        for (pattern, severity, reason) in Self.allPatterns {
            if content.contains(pattern) {
                let safePattern = pattern
                    .replacingOccurrences(of: " ", with: "_")
                    .replacingOccurrences(of: "/", with: "_")
                    .lowercased()

                findings.append(Finding(
                    id: "script_\(safePattern)",
                    category: .heuristic,
                    severity: severity,
                    confidence: .medium,
                    summary: reason,
                    evidence: "Found '\(pattern)' in script",
                    location: location,
                    remediation: "Review script to confirm this operation is expected."
                ))
            }
        }

        return findings
    }

    /// Detects obfuscation techniques
    private func detectObfuscation(content: String, location: String?) -> [Finding] {
        var findings: [Finding] = []

        // Detect very long lines (possible obfuscation)
        let lines = content.components(separatedBy: "\n")
        if let maxLine = lines.max(by: { $0.count < $1.count }), maxLine.count > 500 {
            findings.append(Finding(
                id: "script_long_line",
                category: .heuristic,
                severity: .medium,
                confidence: .medium,
                summary: "Script contains very long line (\(maxLine.count) chars)",
                evidence: "Line length exceeds 500 characters",
                location: location,
                remediation: "Very long lines may indicate obfuscated code."
            ))
        }

        // Detect string concatenation obfuscation patterns
        if content.contains("\"\"") || content.contains("''" ) {
            findings.append(Finding(
                id: "script_string_concat_obfuscation",
                category: .heuristic,
                severity: .medium,
                confidence: .low,
                summary: "Script may use string concatenation obfuscation",
                evidence: "Found repeated empty string patterns",
                location: location,
                remediation: "Check for obfuscated command construction."
            ))
        }

        return findings
    }

    /// Checks script length
    private func checkScriptLength(content: String, location: String?) -> Finding? {
        let lineCount = content.components(separatedBy: "\n").count
        if lineCount > 200 {
            return Finding(
                id: "script_long",
                category: .heuristic,
                severity: .low,
                confidence: .low,
                summary: "Script is unusually long (\(lineCount) lines)",
                evidence: "Line count: \(lineCount)",
                location: location,
                remediation: "Long scripts may contain hidden malicious code."
            )
        }
        return nil
    }
}
