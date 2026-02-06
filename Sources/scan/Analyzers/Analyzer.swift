import Foundation

/// Context provided to each analyzer
struct AnalysisContext: Sendable {
    /// Metadata about the original file
    let metadata: FileMetadata
    /// URL of the original file
    let fileURL: URL
    /// Root directory of unpacked contents (nil for non-containers)
    let contentRoot: URL?
    /// Manifest of unpacked contents (nil for non-containers)
    let manifest: Manifest?
    /// Scan options
    let options: ScanOptions
    /// Logger
    let logger: VerboseLogger
}

/// Protocol for static analysis modules
protocol Analyzer: Sendable {
    /// Unique name for this analyzer
    var name: String { get }

    /// Whether this analyzer can analyze the given file
    func canAnalyze(_ context: AnalysisContext) -> Bool

    /// Perform analysis and return findings
    func analyze(_ context: AnalysisContext) async throws -> [Finding]
}
