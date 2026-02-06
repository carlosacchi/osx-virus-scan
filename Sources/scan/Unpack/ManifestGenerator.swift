import Foundation

/// Generates a manifest of files from an unpacked container
struct ManifestGenerator: Sendable {
    private let logger: VerboseLogger

    init(logger: VerboseLogger) {
        self.logger = logger
    }

    /// Walk the extracted directory tree and build a manifest
    func generate(rootURL: URL) throws -> Manifest {
        var entries: [ManifestEntry] = []
        var totalSize: UInt64 = 0

        let detector = FileTypeDetector()
        let hasher = HashCalculator()
        let basePath = rootURL.standardizedFileURL.path

        guard let enumerator = FileManager.default.enumerator(
            at: rootURL,
            includingPropertiesForKeys: [
                .fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey,
                .isDirectoryKey, .isExecutableKey
            ],
            options: []
        ) else {
            return Manifest(entries: [], totalSize: 0, totalFiles: 0)
        }

        while let fileURL = enumerator.nextObject() as? URL {
            let resourceValues = try? fileURL.resourceValues(forKeys: [
                .fileSizeKey, .isRegularFileKey, .isSymbolicLinkKey,
                .isDirectoryKey, .isExecutableKey
            ])

            // Skip directories in the manifest (but traverse them)
            if resourceValues?.isDirectory == true && resourceValues?.isSymbolicLink != true {
                continue
            }

            let relativePath = String(fileURL.path.dropFirst(basePath.count + 1))
            let size = UInt64(resourceValues?.fileSize ?? 0)
            let isExecutable = resourceValues?.isExecutable ?? false
            let isSymlink = resourceValues?.isSymbolicLink ?? false

            // Detect type
            let type = isSymlink ? FileType.unknown : detector.detect(url: fileURL)

            // Compute hash for executables and scripts (skip for symlinks)
            var sha256: String?
            if !isSymlink && (isExecutable || type == .machO || type == .script) {
                sha256 = try? hasher.sha256(of: fileURL)
            }

            // Read symlink target
            var symlinkTarget: String?
            if isSymlink {
                symlinkTarget = try? FileManager.default.destinationOfSymbolicLink(atPath: fileURL.path)
            }

            entries.append(ManifestEntry(
                relativePath: relativePath,
                size: size,
                type: type,
                sha256: sha256,
                isExecutable: isExecutable,
                isSymlink: isSymlink,
                symlinkTarget: symlinkTarget
            ))

            totalSize += size
        }

        logger.info("Manifest: \(entries.count) files, \(ByteCountFormatter.string(fromByteCount: Int64(totalSize), countStyle: .file))")

        return Manifest(
            entries: entries,
            totalSize: totalSize,
            totalFiles: entries.count
        )
    }
}
