import Foundation

/// Reports scan progress to stderr so the user knows what's happening
final class ProgressReporter: @unchecked Sendable {
    private let enabled: Bool
    private let stderr = FileHandle.standardError

    private let dim = "\u{001B}[2m"
    private let bold = "\u{001B}[1m"
    private let cyan = "\u{001B}[36m"
    private let green = "\u{001B}[32m"
    private let reset = "\u{001B}[0m"

    init(enabled: Bool) {
        self.enabled = enabled
    }

    func banner() {
        guard enabled else { return }
        write("\(bold)scan v\(ToolInfo.current.version)\(reset) — Static File Analyzer for macOS\n")
    }

    func scanTarget(name: String, size: String, type: String) {
        guard enabled else { return }
        write("Scanning: \(bold)\(name)\(reset) (\(size), \(type))\n\n")
    }

    func step(_ description: String) {
        guard enabled else { return }
        write("  \(dim)▸\(reset) \(description)\n")
    }

    func done(duration: TimeInterval) {
        guard enabled else { return }
        let formatted = String(format: "%.1f", duration)
        write("  \(green)✓\(reset) Complete (\(formatted)s)\n\n")
    }

    private func write(_ text: String) {
        stderr.write(Data(text.utf8))
    }
}
