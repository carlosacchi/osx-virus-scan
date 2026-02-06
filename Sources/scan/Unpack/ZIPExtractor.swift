import Foundation

/// Extracts ZIP archives with Zip Slip and symlink escape protection
final class ZIPExtractor: Unpacker, @unchecked Sendable {
    let supportedTypes: [FileType] = [.zip]

    private let shell = ShellRunner()
    private let logger: VerboseLogger
    private var extractionDir: URL?

    /// Maximum allowed compression ratio (decompressed/compressed)
    private static let maxCompressionRatio: Double = 100.0
    /// Maximum depth of nested directories
    private static let maxDepth = 50

    init(logger: VerboseLogger) {
        self.logger = logger
    }

    func unpack(source: URL, into destination: URL) async throws -> UnpackResult {
        var findings: [Finding] = []

        logger.info("Extracting ZIP: \(source.lastPathComponent)")

        let extractDir = destination.appendingPathComponent("zip-extract")
        try FileManager.default.createDirectory(at: extractDir, withIntermediateDirectories: true)
        extractionDir = extractDir

        // Use ditto for extraction (macOS native, handles resource forks)
        let result = try await shell.run(
            executable: "/usr/bin/ditto",
            arguments: ["-xk", source.path, extractDir.path],
            timeout: 120
        )

        if !result.succeeded {
            // Check for password-protected archive
            if result.stderr.contains("password") || result.stderr.contains("encrypted") {
                throw ScanError.encryptedContainer(path: source.path)
            }
            throw ScanError.unpackFailed(
                type: .zip,
                reason: "ditto extraction failed (exit \(result.exitCode)): \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }

        // Security: validate no path escapes (Zip Slip protection)
        let escapeFindings = try validateNoEscape(extractionDir: extractDir)
        findings.append(contentsOf: escapeFindings)

        logger.info("ZIP extracted to: \(extractDir.path)")

        return UnpackResult(
            contentRoot: extractDir,
            findings: findings
        )
    }

    func cleanup() async {
        // Extraction dir will be cleaned up with the temp directory
        extractionDir = nil
    }

    // MARK: - Security validation

    /// Walk all extracted files and verify none escape the extraction directory
    private func validateNoEscape(extractionDir: URL) throws -> [Finding] {
        var findings: [Finding] = []
        let basePath = extractionDir.standardizedFileURL.path

        guard let enumerator = FileManager.default.enumerator(
            at: extractionDir,
            includingPropertiesForKeys: [.isSymbolicLinkKey, .isDirectoryKey],
            options: []
        ) else {
            return findings
        }

        var depth = 0

        while let fileURL = enumerator.nextObject() as? URL {
            // Check directory depth
            let relativePath = fileURL.path.replacingOccurrences(of: basePath, with: "")
            let currentDepth = relativePath.components(separatedBy: "/").count
            depth = max(depth, currentDepth)

            if depth > Self.maxDepth {
                findings.append(Finding(
                    id: "zip_excessive_depth",
                    category: .packaging,
                    severity: .medium,
                    confidence: .high,
                    summary: "ZIP contains excessively deep directory nesting (\(depth) levels)",
                    evidence: "Path: \(relativePath)",
                    location: relativePath,
                    remediation: "Inspect the archive manually for potential zip bomb"
                ))
                break
            }

            // Check symlinks
            let resourceValues = try? fileURL.resourceValues(forKeys: [.isSymbolicLinkKey])
            if resourceValues?.isSymbolicLink == true {
                // Resolve the symlink and check if it escapes
                let resolved = fileURL.resolvingSymlinksInPath().standardizedFileURL.path
                if !resolved.hasPrefix(basePath) {
                    findings.append(Finding(
                        id: "zip_symlink_escape",
                        category: .packaging,
                        severity: .high,
                        confidence: .high,
                        summary: "Symlink escapes extraction directory (potential Zip Slip)",
                        evidence: "Symlink '\(fileURL.lastPathComponent)' points to '\(resolved)' which is outside '\(basePath)'",
                        location: relativePath,
                        remediation: "Do not trust this archive. The symlink attempts to access files outside the archive."
                    ))

                    // Remove the dangerous symlink
                    try? FileManager.default.removeItem(at: fileURL)
                }
            }

            // Check for path traversal in filenames
            let resolved = fileURL.resolvingSymlinksInPath().standardizedFileURL.path
            if !resolved.hasPrefix(basePath) {
                throw ScanError.zipSlipDetected(
                    path: fileURL.path,
                    resolved: resolved
                )
            }
        }

        return findings
    }
}
