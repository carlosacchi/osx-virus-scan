import Testing
import Foundation
@testable import scan

@Suite("FileTypeDetector Tests")
struct FileTypeDetectorTests {

    let detector = FileTypeDetector()

    @Test("Detect Mach-O binary")
    func machOBinary() {
        let result = detector.detect(url: URL(fileURLWithPath: "/bin/ls"))
        #expect(result == .machO)
    }

    @Test("Detect app bundle")
    func appBundle() {
        let result = detector.detect(url: URL(fileURLWithPath: "/System/Applications/Calculator.app"))
        #expect(result == .app)
    }

    @Test("Detect file by magic bytes - ZIP")
    func zipMagicBytes() throws {
        let tmpFile = "/tmp/scan-test-zip-\(UUID().uuidString).dat"
        let zipHeader = Data([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00])
        try zipHeader.write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .zip)
    }

    @Test("Detect file by magic bytes - PKG/xar")
    func pkgMagicBytes() throws {
        let tmpFile = "/tmp/scan-test-pkg-\(UUID().uuidString).dat"
        let xarHeader = Data([0x78, 0x61, 0x72, 0x21, 0x00, 0x00, 0x00, 0x00])
        try xarHeader.write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .pkg)
    }

    @Test("Detect file by magic bytes - script shebang")
    func scriptShebang() throws {
        let tmpFile = "/tmp/scan-test-script-\(UUID().uuidString).sh"
        try Data("#!/bin/bash\necho hello".utf8).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .script)
    }

    @Test("Detect file by extension - DMG")
    func dmgExtension() throws {
        let tmpFile = "/tmp/scan-test-\(UUID().uuidString).dmg"
        try Data("not a real dmg".utf8).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .dmg)
    }

    @Test("Unknown file type for random data")
    func unknownType() throws {
        let tmpFile = "/tmp/scan-test-unknown-\(UUID().uuidString).dat"
        try Data([0x00, 0x01, 0x02, 0x03]).write(to: URL(fileURLWithPath: tmpFile))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .unknown)
    }

    @Test("Empty file returns unknown")
    func emptyFile() throws {
        let tmpFile = "/tmp/scan-test-empty-\(UUID().uuidString).dat"
        FileManager.default.createFile(atPath: tmpFile, contents: Data())
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        #expect(detector.detect(url: URL(fileURLWithPath: tmpFile)) == .unknown)
    }
}
