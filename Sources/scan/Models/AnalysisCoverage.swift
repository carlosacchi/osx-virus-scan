import Foundation

/// Analysis coverage information for transparency
struct AnalysisCoverage: Codable, Sendable {
    let totalAnalyzers: Int
    let applicableAnalyzers: Int
    let analyzersRun: [String]
    let findingsBySeverity: [String: Int]  // "high": 2, "medium": 5, etc.
    let categoriesCovered: [String]
    let executionTime: Double
}
