import Foundation

/// Result of an unpack operation
struct UnpackResult: Sendable {
    /// Root directory containing unpacked contents
    let contentRoot: URL
    /// Any findings generated during unpacking (e.g., encrypted archive, multiple partitions)
    let findings: [Finding]
}

/// Protocol for container unpackers (DMG, ZIP, PKG)
protocol Unpacker: Sendable {
    /// File types this unpacker handles
    var supportedTypes: [FileType] { get }

    /// Unpack the source into the destination directory
    /// - Parameters:
    ///   - source: Path to the container file
    ///   - destination: Temp directory to unpack into
    /// - Returns: UnpackResult with content root and any findings
    func unpack(source: URL, into destination: URL) async throws -> UnpackResult

    /// Clean up any resources (e.g., unmount DMG volumes)
    func cleanup() async
}
