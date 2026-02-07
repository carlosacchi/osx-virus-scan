import Foundation

/// Tool identification for JSON output
struct ToolInfo: Codable, Sendable {
    let name: String
    let version: String

    static let current = ToolInfo(name: "scan", version: "0.8.0")
}

/// Top-level scan result containing all findings and metadata
struct ScanResult: Codable, Sendable {
    /// Tool identification
    let tool: ToolInfo
    /// ISO-8601 timestamp of the scan
    let timestamp: String
    /// Input file information
    let input: InputInfo
    /// Overall verdict
    let verdict: Verdict
    /// Numeric score (0-100, higher = more suspicious)
    let score: Int
    /// File metadata
    let metadata: FileMetadata
    /// Container manifest (for DMG/ZIP/PKG), nil for non-containers
    let manifest: Manifest?
    /// Individual findings from analyzers
    let findings: [Finding]
    /// Errors encountered during scanning
    let errors: [ScanErrorRecord]
    /// Scan duration in seconds
    let scanDuration: Double
}

/// Information about the scan input
struct InputInfo: Codable, Sendable {
    let path: String
    let type: FileType
}
