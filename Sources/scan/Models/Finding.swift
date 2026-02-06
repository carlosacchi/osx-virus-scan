import Foundation

/// Category of a finding, mapping to the analysis domain
enum FindingCategory: String, Codable, Sendable {
    case signature
    case notarization
    case persistence
    case packaging
    case heuristic
    case signatureDB = "signature_db"
    case yara
    case reputation
    case metadata
}

/// Confidence level for a finding
enum Confidence: String, Codable, Sendable {
    case low = "Low"
    case medium = "Medium"
    case high = "High"
}

/// A single finding from an analyzer
struct Finding: Codable, Sendable {
    /// Unique identifier for the finding type (e.g., "codesign_invalid", "unsigned_binary")
    let id: String
    /// Category of analysis that produced this finding
    let category: FindingCategory
    /// Severity level
    let severity: Verdict
    /// Confidence in the finding
    let confidence: Confidence
    /// Short human-readable summary
    let summary: String
    /// Detailed evidence supporting the finding
    let evidence: String
    /// Path inside extracted tree, if applicable
    let location: String?
    /// Suggested remediation action
    let remediation: String?
}
