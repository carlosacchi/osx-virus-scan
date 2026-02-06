import Foundation

/// Manages a temporary working directory with guaranteed cleanup
final class TempDirectory: Sendable {
    let url: URL

    init() throws {
        let id = UUID().uuidString
        let path = URL(fileURLWithPath: "/tmp/scan-\(id)")
        try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
        self.url = path
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: url)
    }
}
