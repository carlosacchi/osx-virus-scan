import Foundation

/// Metadata collected about a scanned file
struct FileMetadata: Codable, Sendable {
    /// Original path provided by the user
    let path: String
    /// Resolved absolute path (after symlink resolution)
    let resolvedPath: String
    /// Whether the original path was a symlink
    let isSymlink: Bool
    /// SHA-256 hash of the file contents
    let sha256: String
    /// File size in bytes
    let sizeBytes: UInt64
    /// Detected file type
    let fileType: FileType
    /// Quarantine attribute info, if present
    let quarantine: QuarantineInfo?
    /// POSIX permissions string (e.g., "rwxr-xr-x")
    let permissions: String
}

extension FileMetadata {
    /// Human-readable file size
    var formattedSize: String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(sizeBytes))
    }
}
