import Foundation

/// A manifest of files found inside a container (DMG, ZIP, PKG)
struct Manifest: Codable, Sendable {
    let entries: [ManifestEntry]
    let totalSize: UInt64
    let totalFiles: Int
}

/// A single entry in a file manifest
struct ManifestEntry: Codable, Sendable {
    /// Path relative to the container root
    let relativePath: String
    /// File size in bytes
    let size: UInt64
    /// Detected file type
    let type: FileType
    /// SHA-256 hash (only computed for executables and scripts)
    let sha256: String?
    /// Whether the file has execute permission
    let isExecutable: Bool
    /// Whether this is a symlink
    let isSymlink: Bool
    /// Symlink target (if isSymlink is true)
    let symlinkTarget: String?
}
