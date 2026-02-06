import Testing
import Foundation
@testable import scan

@Suite("OutputFormatter Tests")
struct OutputFormatterTests {

    let sampleResult = ScanResult(
        tool: .current,
        timestamp: "2025-01-01T00:00:00Z",
        input: InputInfo(path: "/test/file.dmg", type: .dmg),
        verdict: .medium,
        score: 25,
        metadata: FileMetadata(
            path: "/test/file.dmg",
            resolvedPath: "/test/file.dmg",
            isSymlink: false,
            sha256: "abc123def456",
            sizeBytes: 1024,
            fileType: .dmg,
            quarantine: nil,
            permissions: "rw-r--r--"
        ),
        manifest: nil,
        findings: [
            Finding(
                id: "test_finding",
                category: .signature,
                severity: .medium,
                confidence: .high,
                summary: "Test finding",
                evidence: "Some evidence",
                location: nil,
                remediation: "Fix it"
            )
        ],
        errors: [],
        scanDuration: 0.5
    )

    @Test("Text formatter includes key fields")
    func textFormatterContent() {
        let formatter = TextFormatter()
        let output = formatter.format(sampleResult)

        #expect(output.contains("/test/file.dmg"))
        #expect(output.contains("DMG"))
        #expect(output.contains("abc123def456"))
        #expect(output.contains("25/100"))
        #expect(output.contains("Test finding"))
        #expect(output.contains("Fix it"))
    }

    @Test("Text formatter shows resolved path for symlinks")
    func textFormatterSymlink() {
        let symlinkMeta = FileMetadata(
            path: "/link/file.dmg",
            resolvedPath: "/real/file.dmg",
            isSymlink: true,
            sha256: "abc123",
            sizeBytes: 100,
            fileType: .dmg,
            quarantine: nil,
            permissions: "rw-r--r--"
        )
        let result = ScanResult(
            tool: sampleResult.tool,
            timestamp: sampleResult.timestamp,
            input: sampleResult.input,
            verdict: sampleResult.verdict,
            score: sampleResult.score,
            metadata: symlinkMeta,
            manifest: nil,
            findings: sampleResult.findings,
            errors: sampleResult.errors,
            scanDuration: sampleResult.scanDuration
        )

        let formatter = TextFormatter()
        let output = formatter.format(result)
        #expect(output.contains("Resolved:"))
        #expect(output.contains("/real/file.dmg"))
    }

    @Test("JSON formatter produces valid JSON")
    func jsonFormatterValid() {
        let formatter = JSONOutputFormatter()
        let output = formatter.format(sampleResult)

        let data = output.data(using: .utf8)!
        let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(json != nil)
        #expect(json?["verdict"] as? String == "Medium")
        #expect(json?["score"] as? Int == 25)
    }

    @Test("JSON round-trips through Codable")
    func jsonRoundTrip() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(sampleResult)
        let decoded = try decoder.decode(ScanResult.self, from: data)

        #expect(decoded.verdict == sampleResult.verdict)
        #expect(decoded.score == sampleResult.score)
        #expect(decoded.metadata.sha256 == sampleResult.metadata.sha256)
        #expect(decoded.findings.count == sampleResult.findings.count)
    }

    @Test("Text formatter shows manifest info")
    func textFormatterManifest() {
        let manifest = Manifest(
            entries: [
                ManifestEntry(relativePath: "app/main", size: 1000, type: .machO,
                              sha256: "deadbeef", isExecutable: true, isSymlink: false, symlinkTarget: nil),
                ManifestEntry(relativePath: "app/readme.txt", size: 200, type: .unknown,
                              sha256: nil, isExecutable: false, isSymlink: false, symlinkTarget: nil),
            ],
            totalSize: 1200,
            totalFiles: 2
        )

        let result = ScanResult(
            tool: .current,
            timestamp: "2025-01-01T00:00:00Z",
            input: InputInfo(path: "/test.zip", type: .zip),
            verdict: .info,
            score: 0,
            metadata: sampleResult.metadata,
            manifest: manifest,
            findings: [],
            errors: [],
            scanDuration: 0.1
        )

        let formatter = TextFormatter()
        let output = formatter.format(result)
        #expect(output.contains("Contents:   2 files"))
        #expect(output.contains("Executables: 1"))
        #expect(output.contains("app/main"))
    }

    @Test("Text formatter shows errors")
    func textFormatterErrors() {
        let result = ScanResult(
            tool: .current,
            timestamp: "2025-01-01T00:00:00Z",
            input: InputInfo(path: "/test", type: .unknown),
            verdict: .error,
            score: 0,
            metadata: sampleResult.metadata,
            manifest: nil,
            findings: [],
            errors: [ScanErrorRecord(step: "hash", message: "Permission denied")],
            scanDuration: 0.1
        )

        let formatter = TextFormatter()
        let output = formatter.format(result)
        #expect(output.contains("Errors (1)"))
        #expect(output.contains("[hash] Permission denied"))
    }
}
