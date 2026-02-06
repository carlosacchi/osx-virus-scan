import Testing
import Foundation
@testable import scan

@Suite("FileIngestor Tests")
struct FileIngestorTests {

    let ingestor = FileIngestor()

    @Test("Ingest valid file returns correct metadata")
    func validFile() throws {
        let result = try ingestor.ingest(path: "/bin/ls")
        #expect(result.resolvedURL.path == "/bin/ls")
        #expect(result.size > 0)
        #expect(!result.isDirectory)
        #expect(result.permissions.count == 9)
    }

    @Test("Ingest nonexistent file throws")
    func nonexistentFile() {
        #expect(throws: ScanError.self) {
            try ingestor.ingest(path: "/nonexistent/file")
        }
    }

    @Test("Ingest directory returns isDirectory true")
    func directoryInput() throws {
        let result = try ingestor.ingest(path: "/tmp")
        #expect(result.isDirectory)
    }

    @Test("Ingest tilde path expands correctly")
    func tildePath() throws {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let result = try ingestor.ingest(path: "~")
        #expect(result.resolvedURL.path == home)
        #expect(result.isDirectory)
    }

    @Test("Ingest absolute path starts with /")
    func absolutePath() throws {
        let tmpFile = "/tmp/scan-test-ingestor-\(UUID().uuidString).txt"
        FileManager.default.createFile(atPath: tmpFile, contents: Data("test".utf8))
        defer { try? FileManager.default.removeItem(atPath: tmpFile) }

        let result = try ingestor.ingest(path: tmpFile)
        #expect(result.resolvedURL.path.hasPrefix("/"))
    }

    @Test("Symlink detection works")
    func symlinkDetection() throws {
        let tmpDir = "/tmp/scan-test-symlink-\(UUID().uuidString)"
        let target = "\(tmpDir)/target.txt"
        let link = "\(tmpDir)/link.txt"
        try FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: target, contents: Data("hello".utf8))
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let result = try ingestor.ingest(path: link)
        #expect(result.isSymlink)
    }

    @Test("Permission formatting is correct")
    func permissionFormat() {
        #expect(FileIngestor.formatPermissions(0o755) == "rwxr-xr-x")
        #expect(FileIngestor.formatPermissions(0o644) == "rw-r--r--")
        #expect(FileIngestor.formatPermissions(0o777) == "rwxrwxrwx")
        #expect(FileIngestor.formatPermissions(0o000) == "---------")
    }
}
