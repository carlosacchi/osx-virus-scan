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

    /// Maximum total extracted size in bytes (2 GB) to prevent disk exhaustion
    private static let maxExtractedSize: UInt64 = 2 * 1024 * 1024 * 1024

    func unpack(source: URL, into destination: URL) async throws -> UnpackResult {
        var findings: [Finding] = []

        logger.info("Extracting ZIP: \(source.lastPathComponent)")

        // Pre-extraction check: use zipinfo to get declared uncompressed size
        let preCheckFindings = try await preExtractionSizeCheck(source: source)
        findings.append(contentsOf: preCheckFindings)
        if preCheckFindings.contains(where: { $0.severity == .high }) {
            // Abort extraction for likely zip bombs
            return UnpackResult(
                contentRoot: destination,
                findings: findings
            )
        }

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

        // Security: check compression ratio (zip bomb detection)
        let ratioFindings = checkCompressionRatio(source: source, extractionDir: extractDir)
        findings.append(contentsOf: ratioFindings)

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

    /// Pre-extraction check: parse zipinfo to get declared uncompressed size before extracting
    private func preExtractionSizeCheck(source: URL) async throws -> [Finding] {
        var findings: [Finding] = []

        guard let compressedAttrs = try? FileManager.default.attributesOfItem(atPath: source.path),
              let compressedSize = compressedAttrs[.size] as? UInt64,
              compressedSize > 0 else {
            return findings
        }

        // zipinfo -t prints a summary line like "123 files, 456789 bytes uncompressed, ..."
        let result = try await shell.run(
            executable: "/usr/bin/zipinfo",
            arguments: ["-t", source.path],
            timeout: 10
        )

        guard result.succeeded else { return findings }

        // Parse declared uncompressed size from summary line
        let line = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if let declaredSize = parseDeclaredSize(from: line) {
            let ratio = Double(declaredSize) / Double(compressedSize)

            if declaredSize > Self.maxExtractedSize || ratio > Self.maxCompressionRatio {
                logger.info("Pre-extraction bomb check: declared \(declaredSize) bytes, ratio \(String(format: "%.0f", ratio)):1")
                findings.append(Finding(
                    id: "zip_bomb_precheck",
                    category: .packaging,
                    severity: .high,
                    confidence: .medium,
                    summary: "Likely zip bomb detected (declared \(Self.formatBytes(declaredSize)), ratio \(String(format: "%.0f", ratio)):1)",
                    evidence: "Compressed: \(compressedSize) bytes, Declared uncompressed: \(declaredSize) bytes. Exceeds safety threshold — extraction aborted.",
                    location: source.lastPathComponent,
                    remediation: "Do not extract this archive. It may exhaust disk space."
                ))
            }
        }

        return findings
    }

    /// Parse the declared uncompressed byte count from zipinfo -t output
    /// Example: "1 file, 12345 bytes uncompressed, 123 bytes compressed:  99.0%"
    private func parseDeclaredSize(from line: String) -> UInt64? {
        // Look for the pattern: "<number> bytes uncompressed"
        let parts = line.components(separatedBy: ",")
        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.hasSuffix("bytes uncompressed") {
                let numStr = trimmed.replacingOccurrences(of: "bytes uncompressed", with: "")
                    .trimmingCharacters(in: .whitespaces)
                return UInt64(numStr)
            }
        }
        return nil
    }

    private static func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(clamping: bytes))
    }

    /// Compare compressed vs decompressed size to detect zip bombs
    private func checkCompressionRatio(source: URL, extractionDir: URL) -> [Finding] {
        var findings: [Finding] = []
        guard let compressedAttrs = try? FileManager.default.attributesOfItem(atPath: source.path),
              let compressedSize = compressedAttrs[.size] as? UInt64,
              compressedSize > 0 else {
            return findings
        }

        let extractedSize = Self.directorySize(url: extractionDir)
        let ratio = Double(extractedSize) / Double(compressedSize)

        if ratio > Self.maxCompressionRatio {
            logger.info("Compression ratio: \(String(format: "%.1f", ratio)):1 (threshold: \(String(format: "%.0f", Self.maxCompressionRatio)):1)")
            findings.append(Finding(
                id: "zip_bomb_ratio",
                category: .packaging,
                severity: .high,
                confidence: .medium,
                summary: "Suspicious compression ratio (\(String(format: "%.0f", ratio)):1)",
                evidence: "Compressed: \(compressedSize) bytes, Extracted: \(extractedSize) bytes, Ratio: \(String(format: "%.1f", ratio)):1 exceeds \(String(format: "%.0f", Self.maxCompressionRatio)):1 threshold",
                location: source.lastPathComponent,
                remediation: "Inspect the archive manually — high compression ratios may indicate a zip bomb"
            ))
        }

        return findings
    }

    /// Recursively sum file sizes in a directory
    private static func directorySize(url: URL) -> UInt64 {
        guard let enumerator = FileManager.default.enumerator(
            at: url,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else { return 0 }

        var total: UInt64 = 0
        while let fileURL = enumerator.nextObject() as? URL {
            guard let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
                  values.isRegularFile == true,
                  let size = values.fileSize else { continue }
            total += UInt64(size)
        }
        return total
    }

    /// Path-boundary-aware containment check (prevents edge cases like /tmp/foo matching /tmp/foobar)
    private func isContained(_ resolvedPath: String, within basePath: String) -> Bool {
        let baseWithSlash = basePath.hasSuffix("/") ? basePath : basePath + "/"
        return resolvedPath == basePath || resolvedPath.hasPrefix(baseWithSlash)
    }

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
                let resolved = fileURL.resolvingSymlinksInPath().standardizedFileURL.path
                if !isContained(resolved, within: basePath) {
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
            if !isContained(resolved, within: basePath) {
                throw ScanError.zipSlipDetected(
                    path: fileURL.path,
                    resolved: resolved
                )
            }
        }

        return findings
    }
}
