import Foundation

/// Logger that respects --verbose and --debug flags
struct VerboseLogger: Sendable {
    let verbose: Bool
    let debug: Bool

    func info(_ message: @autoclosure () -> String) {
        if verbose || debug {
            FileHandle.standardError.write(Data("[info] \(message())\n".utf8))
        }
    }

    func debug(_ message: @autoclosure () -> String) {
        if debug {
            FileHandle.standardError.write(Data("[debug] \(message())\n".utf8))
        }
    }

    func error(_ message: @autoclosure () -> String) {
        FileHandle.standardError.write(Data("[error] \(message())\n".utf8))
    }
}
