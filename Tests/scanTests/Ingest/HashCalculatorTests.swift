import Testing
import Foundation
@testable import scan

@Suite("HashCalculator Tests")
struct HashCalculatorTests {

    let calculator = HashCalculator()

    @Test("SHA-256 of empty file matches known value")
    func emptyFileHash() throws {
        let tmpFile = "/tmp/scan-test-hash-empty-\(UUID().uuidString)"
        FileManager.default.createFile(atPath: tmpFile, contents: Data())
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let hash = try calculator.sha256(of: URL(fileURLWithPath: tmpFile))
        #expect(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("SHA-256 of known content matches expected value")
    func knownContentHash() throws {
        let tmpFile = "/tmp/scan-test-hash-known-\(UUID().uuidString)"
        try Data("hello world\n".utf8).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let hash = try calculator.sha256(of: URL(fileURLWithPath: tmpFile))
        #expect(hash == "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447")
    }

    @Test("SHA-256 is deterministic")
    func deterministic() throws {
        let tmpFile = "/tmp/scan-test-hash-det-\(UUID().uuidString)"
        try Data("test data".utf8).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let hash1 = try calculator.sha256(of: URL(fileURLWithPath: tmpFile))
        let hash2 = try calculator.sha256(of: URL(fileURLWithPath: tmpFile))
        #expect(hash1 == hash2)
    }

    @Test("SHA-256 produces 64-character hex string")
    func hashLength() throws {
        let tmpFile = "/tmp/scan-test-hash-len-\(UUID().uuidString)"
        try Data("some content".utf8).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let hash = try calculator.sha256(of: URL(fileURLWithPath: tmpFile))
        #expect(hash.count == 64)
        #expect(hash.allSatisfy { $0.isHexDigit })
    }

    @Test("Nonexistent file throws error")
    func nonexistentFile() {
        #expect(throws: (any Error).self) {
            try calculator.sha256(of: URL(fileURLWithPath: "/nonexistent/file"))
        }
    }
}
