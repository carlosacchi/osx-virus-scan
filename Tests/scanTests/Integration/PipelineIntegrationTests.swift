import Testing
import Foundation
@testable import scan

@Suite("Pipeline Integration Tests")
struct PipelineIntegrationTests {

    let options = ScanOptions.default
    let logger = VerboseLogger(verbose: false, debug: false)

    @Test("Scan system binary produces valid result")
    func scanSystemBinary() async throws {
        let pipeline = Pipeline(options: options, logger: logger)
        let result = try await pipeline.run(path: "/bin/ls")

        #expect(result.verdict == .low || result.verdict == .info)
        #expect(result.metadata.fileType == .machO)
        #expect(!result.metadata.sha256.isEmpty)
        #expect(result.metadata.sizeBytes > 0)
        #expect(result.errors.isEmpty)
        #expect(result.manifest == nil)
    }

    @Test("Scan app bundle finds code signing and gatekeeper findings")
    func scanAppBundle() async throws {
        let pipeline = Pipeline(options: options, logger: logger)
        let result = try await pipeline.run(path: "/System/Applications/Calculator.app")

        #expect(result.metadata.fileType == .app)
        #expect(result.manifest == nil) // Not a container
        #expect(result.errors.isEmpty)
        #expect(result.findings.contains { $0.id == "codesign_valid" })
        #expect(result.findings.contains { $0.id == "gatekeeper_accepted" })
    }

    @Test("Scan nonexistent path throws ScanError")
    func scanNonexistent() async {
        let pipeline = Pipeline(options: options, logger: logger)
        await #expect(throws: ScanError.self) {
            try await pipeline.run(path: "/nonexistent/path")
        }
    }

    @Test("Scan ZIP produces manifest")
    func scanZIP() async throws {
        let tmpDir = "/tmp/scan-inttest-\(UUID().uuidString)"
        let zipPath = "\(tmpDir).zip"
        try FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        try Data("hello".utf8).write(to: URL(fileURLWithPath: "\(tmpDir)/test.txt"))
        defer {
            try? FileManager.default.removeItem(atPath: tmpDir)
            try? FileManager.default.removeItem(atPath: zipPath)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        process.arguments = ["-ck", tmpDir, zipPath]
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            Issue.record("Failed to create test ZIP")
            return
        }

        let pipeline = Pipeline(options: options, logger: logger)
        let result = try await pipeline.run(path: zipPath)

        #expect(result.metadata.fileType == .zip)
        #expect(result.manifest != nil)
        #expect(result.manifest!.totalFiles > 0)
        #expect(!result.metadata.sha256.isEmpty)
    }

    @Test("Scan DMG produces manifest")
    func scanDMG() async throws {
        let dmgPath = "/tmp/scan-inttest-\(UUID().uuidString).dmg"
        defer { try? FileManager.default.removeItem(atPath: dmgPath) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = ["create", "-size", "1m", "-volname", "IntTest", "-fs", "HFS+", "-ov", dmgPath]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            Issue.record("Failed to create test DMG")
            return
        }

        let pipeline = Pipeline(options: options, logger: logger)
        let result = try await pipeline.run(path: dmgPath)

        #expect(result.metadata.fileType == .dmg)
        #expect(result.manifest != nil)
        #expect(!result.metadata.sha256.isEmpty)
    }

    @Test("JSON output is valid and round-trips")
    func jsonOutputValid() async throws {
        let pipeline = Pipeline(options: options, logger: logger)
        let result = try await pipeline.run(path: "/bin/ls")

        let formatter = JSONOutputFormatter()
        let json = formatter.format(result)

        let data = json.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ScanResult.self, from: data)

        #expect(decoded.verdict == result.verdict)
        #expect(decoded.score == result.score)
        #expect(decoded.metadata.sha256 == result.metadata.sha256)
    }

    @Test("Strict mode throws on nonexistent path")
    func strictMode() async {
        let strictOptions = ScanOptions(
            json: false, verbose: false, debug: false,
            strict: true, offline: true, reputation: false, noCleanup: false
        )
        let pipeline = Pipeline(options: strictOptions, logger: logger)

        await #expect(throws: (any Error).self) {
            try await pipeline.run(path: "/nonexistent")
        }
    }
}
