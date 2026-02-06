import Foundation

/// Errors that can occur during scanning
enum ScanError: Error, Sendable {
    case fileNotFound(path: String)
    case fileNotReadable(path: String)
    case notAFile(path: String)
    case invalidPath(path: String, reason: String)
    case hashFailed(path: String, reason: String)
    case unpackFailed(type: FileType, reason: String)
    case zipSlipDetected(path: String, resolved: String)
    case analyzerFailed(name: String, reason: String)
    case subprocessFailed(command: String, exitCode: Int32, stderr: String)
    case subprocessTimeout(command: String, timeout: TimeInterval)
    case encryptedContainer(path: String)
    case networkError(reason: String)
}

/// A recorded error for inclusion in scan output
struct ScanErrorRecord: Codable, Sendable {
    let step: String
    let message: String
}

extension ScanError: CustomStringConvertible {
    var description: String {
        switch self {
        case .fileNotFound(let path):
            return "File not found: \(path)"
        case .fileNotReadable(let path):
            return "File not readable: \(path)"
        case .notAFile(let path):
            return "Not a regular file: \(path)"
        case .invalidPath(let path, let reason):
            return "Invalid path '\(path)': \(reason)"
        case .hashFailed(let path, let reason):
            return "Hash calculation failed for '\(path)': \(reason)"
        case .unpackFailed(let type, let reason):
            return "Failed to unpack \(type.displayName): \(reason)"
        case .zipSlipDetected(let path, let resolved):
            return "Zip Slip detected: '\(path)' resolves to '\(resolved)'"
        case .analyzerFailed(let name, let reason):
            return "Analyzer '\(name)' failed: \(reason)"
        case .subprocessFailed(let command, let exitCode, let stderr):
            return "Command '\(command)' failed (exit \(exitCode)): \(stderr)"
        case .subprocessTimeout(let command, let timeout):
            return "Command '\(command)' timed out after \(timeout)s"
        case .encryptedContainer(let path):
            return "Encrypted container: \(path)"
        case .networkError(let reason):
            return "Network error: \(reason)"
        }
    }
}
