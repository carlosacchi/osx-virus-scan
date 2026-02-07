import Foundation

/// Aggregates findings into a numeric score and overall verdict
struct ScoringEngine: Sendable {
    let config: ScoringConfig

    init(config: ScoringConfig = .default) {
        self.config = config
    }

    /// Evaluate findings and produce a score (0-100) and verdict
    func evaluate(findings: [Finding]) -> (verdict: Verdict, score: Int) {
        let rawScore = findings.reduce(0) { total, finding in
            total + (config.weights[finding.severity] ?? 0)
        }
        let clampedScore = min(max(rawScore, 0), 100)

        // Force High verdict if ANY finding has High severity
        // (prevents single High finding from being classified as Medium)
        if findings.contains(where: { $0.severity == .high }) {
            return (.high, clampedScore)
        }

        let verdict = config.thresholds
            .first { clampedScore <= $0.maxScore }?
            .verdict ?? .high

        return (verdict, clampedScore)
    }
}
