import Foundation

/// Result of file ingestion containing normalized path info and basic attributes
struct IngestResult: Sendable {
    let originalPath: String
    let resolvedURL: URL
    let isSymlink: Bool
    let size: UInt64
    let permissions: String
    let isDirectory: Bool
}

/// Normalizes file paths, validates existence/permissions, and resolves symlinks
struct FileIngestor: Sendable {

    func ingest(path: String) throws -> IngestResult {
        // Expand tilde if present
        let expanded = NSString(string: path).expandingTildeInPath

        // Convert to absolute URL
        let originalURL: URL
        if expanded.hasPrefix("/") {
            originalURL = URL(fileURLWithPath: expanded).standardized
        } else {
            // Relative path: resolve against current working directory
            let cwd = FileManager.default.currentDirectoryPath
            originalURL = URL(fileURLWithPath: cwd)
                .appendingPathComponent(expanded)
                .standardized
        }

        // Resolve symlinks
        let resolvedURL = originalURL.resolvingSymlinksInPath()
        let isSymlink = originalURL.path != resolvedURL.path

        // Check existence
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: resolvedURL.path, isDirectory: &isDirectory) else {
            throw ScanError.fileNotFound(path: resolvedURL.path)
        }

        // Check readability
        guard FileManager.default.isReadableFile(atPath: resolvedURL.path) else {
            throw ScanError.fileNotReadable(path: resolvedURL.path)
        }

        // Reject device files
        let attributes = try FileManager.default.attributesOfItem(atPath: resolvedURL.path)
        let fileType = attributes[.type] as? FileAttributeType
        if fileType == .typeCharacterSpecial || fileType == .typeBlockSpecial || fileType == .typeSocket {
            throw ScanError.invalidPath(path: resolvedURL.path, reason: "Device or socket files cannot be scanned")
        }

        // Get size
        let size = attributes[.size] as? UInt64 ?? 0

        // Get POSIX permissions
        let posixPerms = attributes[.posixPermissions] as? Int ?? 0
        let permissions = Self.formatPermissions(posixPerms)

        return IngestResult(
            originalPath: path,
            resolvedURL: resolvedURL,
            isSymlink: isSymlink,
            size: size,
            permissions: permissions,
            isDirectory: isDirectory.boolValue
        )
    }

    /// Format POSIX permission bits as rwxrwxrwx string
    static func formatPermissions(_ mode: Int) -> String {
        var result = ""
        let flags = [(0o400, "r"), (0o200, "w"), (0o100, "x"),
                     (0o040, "r"), (0o020, "w"), (0o010, "x"),
                     (0o004, "r"), (0o002, "w"), (0o001, "x")]
        for (bit, char) in flags {
            result += (mode & bit != 0) ? char : "-"
        }
        return result
    }
}
