import Foundation

/// Configuration for the scoring engine
struct ScoringConfig: Sendable {
    /// Weight applied per finding based on severity
    let weights: [Verdict: Int]

    /// Score thresholds mapping to overall verdicts (sorted ascending by maxScore)
    let thresholds: [(maxScore: Int, verdict: Verdict)]

    static let `default` = ScoringConfig(
        weights: [
            .info: 0,
            .low: 5,
            .medium: 15,
            .high: 30,
            .unknown: 10,
            .error: 5,
        ],
        thresholds: [
            (0, .info),
            (10, .low),
            (30, .medium),
            (Int.max, .high),
        ]
    )
}
