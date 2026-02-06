import Foundation

/// Analyzes Mach-O binary headers, architectures, and linked libraries
struct MachOAnalyzer: Analyzer, Sendable {
    let name = "macho"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        return context.metadata.fileType == .machO || context.metadata.fileType == .app
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        // For .app bundles, find the main executable
        let binaryURL: URL
        if context.metadata.fileType == .app {
            let macosDir = context.fileURL.appendingPathComponent("Contents/MacOS")
            guard let contents = try? FileManager.default.contentsOfDirectory(
                at: macosDir, includingPropertiesForKeys: nil
            ), let first = contents.first else {
                return findings
            }
            binaryURL = first
        } else {
            binaryURL = context.fileURL
        }

        // Read magic bytes
        let magicFindings = analyzeMagicBytes(url: binaryURL)
        findings.append(contentsOf: magicFindings)

        // Analyze linked libraries via otool
        let dylibFindings = try await analyzeLinkedLibraries(url: binaryURL, logger: context.logger)
        findings.append(contentsOf: dylibFindings)

        return findings
    }

    // MARK: - Magic bytes analysis

    private func analyzeMagicBytes(url: URL) -> [Finding] {
        var findings: [Finding] = []

        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe),
              data.count >= 4 else {
            return findings
        }

        let magic = data.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        var archInfo = ""
        switch magic {
        case 0xFEEDFACF: // MH_MAGIC_64 (LE on ARM/x86)
            archInfo = "64-bit Mach-O"
        case 0xFEEDFACE: // MH_MAGIC (32-bit)
            archInfo = "32-bit Mach-O"
            findings.append(Finding(
                id: "macho_32bit",
                category: .heuristic,
                severity: .low,
                confidence: .high,
                summary: "32-bit Mach-O binary",
                evidence: "macOS 10.15+ does not support 32-bit binaries",
                location: nil,
                remediation: "This binary cannot run on modern macOS. It may be an old or legacy component."
            ))
        case 0xCAFEBABE: // FAT/Universal
            archInfo = "Universal Mach-O (FAT)"
            if data.count >= 8 {
                let archCount = data.subdata(in: 4..<8).withUnsafeBytes {
                    UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
                }
                archInfo += " (\(archCount) architectures)"
            }
        case 0xCFFAEDFE: // MH_MAGIC_64 big-endian
            archInfo = "64-bit Mach-O (big-endian)"
        case 0xCEFAEDFE: // MH_MAGIC 32-bit big-endian
            archInfo = "32-bit Mach-O (big-endian)"
        default:
            return findings
        }

        findings.append(Finding(
            id: "macho_arch",
            category: .metadata,
            severity: .info,
            confidence: .high,
            summary: archInfo,
            evidence: "Magic: 0x\(String(format: "%08X", magic))",
            location: nil,
            remediation: nil
        ))

        return findings
    }

    // MARK: - Linked library analysis

    private func analyzeLinkedLibraries(url: URL, logger: VerboseLogger) async throws -> [Finding] {
        var findings: [Finding] = []
        let shell = ShellRunner()

        // otool -L lists linked dynamic libraries
        let result = try await shell.run(
            executable: "/usr/bin/otool",
            arguments: ["-L", url.path],
            timeout: 15
        )

        guard result.succeeded else { return findings }

        let lines = result.stdout.components(separatedBy: "\n")
        var suspiciousLibs: [String] = []
        var rpathLibs: [String] = []

        for line in lines.dropFirst() { // First line is the binary path
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { continue }

            // Extract library path (before the version info in parentheses)
            let libPath = trimmed.components(separatedBy: " (").first?
                .trimmingCharacters(in: .whitespaces) ?? trimmed

            // Flag libraries not in standard system locations
            let systemPrefixes = ["/usr/lib/", "/System/Library/", "/Library/Apple/"]
            let isSystem = systemPrefixes.contains { libPath.hasPrefix($0) }

            if libPath.hasPrefix("@rpath") || libPath.hasPrefix("@loader_path")
                || libPath.hasPrefix("@executable_path") {
                rpathLibs.append(libPath)
            } else if !isSystem && !libPath.isEmpty && libPath.hasPrefix("/") {
                suspiciousLibs.append(libPath)
            }
        }

        if !suspiciousLibs.isEmpty {
            findings.append(Finding(
                id: "macho_nonstandard_dylib",
                category: .heuristic,
                severity: .medium,
                confidence: .medium,
                summary: "Linked to \(suspiciousLibs.count) non-system dynamic library(ies)",
                evidence: suspiciousLibs.joined(separator: "\n"),
                location: nil,
                remediation: "Non-system libraries could indicate bundled dependencies or potentially injected code."
            ))
        }

        if !rpathLibs.isEmpty {
            findings.append(Finding(
                id: "macho_rpath_libs",
                category: .metadata,
                severity: .info,
                confidence: .high,
                summary: "\(rpathLibs.count) library(ies) loaded via @rpath/@loader_path",
                evidence: rpathLibs.joined(separator: "\n"),
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }
}
