import CryptoKit
import Foundation

/// Computes SHA-256 hash of a file using streaming (constant memory usage)
struct HashCalculator: Sendable {

    /// Buffer size for streaming reads (1 MB)
    private static let bufferSize = 1_048_576

    /// Compute SHA-256 hash of file at the given URL
    /// - Parameter url: File URL to hash
    /// - Returns: Lowercase hex-encoded SHA-256 hash
    func sha256(of url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { handle.closeFile() }

        var hasher = SHA256()

        while autoreleasepool(invoking: {
            let chunk = handle.readData(ofLength: Self.bufferSize)
            guard !chunk.isEmpty else { return false }
            hasher.update(data: chunk)
            return true
        }) {}

        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
