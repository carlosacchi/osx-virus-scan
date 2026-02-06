import Testing
import Foundation
@testable import scan

@Suite("ScoringEngine Tests")
struct ScoringEngineTests {

    let engine = ScoringEngine()

    @Test("No findings returns info verdict with score 0")
    func noFindings() {
        let (verdict, score) = engine.evaluate(findings: [])
        #expect(verdict == .info)
        #expect(score == 0)
    }

    @Test("Info finding keeps score at 0")
    func infoFinding() {
        let findings = [makeFinding(severity: .info)]
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(verdict == .info)
        #expect(score == 0)
    }

    @Test("Low finding produces score 5")
    func lowFinding() {
        let findings = [makeFinding(severity: .low)]
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(verdict == .low)
        #expect(score == 5)
    }

    @Test("Medium finding produces score 15")
    func mediumFinding() {
        let findings = [makeFinding(severity: .medium)]
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(verdict == .medium)
        #expect(score == 15)
    }

    @Test("High finding produces score 30")
    func highFinding() {
        let findings = [makeFinding(severity: .high)]
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(verdict == .medium) // 30 <= 30 threshold -> medium
        #expect(score == 30)
    }

    @Test("Multiple high findings clamp at 100")
    func multipleHighFindings() {
        let findings = Array(repeating: makeFinding(severity: .high), count: 5)
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(verdict == .high)
        #expect(score == 100) // 5 * 30 = 150, clamped to 100
    }

    @Test("Mixed findings sum correctly")
    func mixedFindings() {
        let findings = [
            makeFinding(severity: .info),   // 0
            makeFinding(severity: .low),    // 5
            makeFinding(severity: .medium), // 15
        ]
        let (verdict, score) = engine.evaluate(findings: findings)
        #expect(score == 20) // 0 + 5 + 15
        #expect(verdict == .medium) // 20 <= 30
    }

    @Test("Threshold boundaries are correct")
    func thresholdBoundaries() {
        // Score exactly 10 -> Low (10 <= 10)
        let twoLow = [makeFinding(severity: .low), makeFinding(severity: .low)]
        let (v1, s1) = engine.evaluate(findings: twoLow)
        #expect(s1 == 10)
        #expect(v1 == .low)

        // Score exactly 30 -> Medium (30 <= 30)
        let twoMedium = [makeFinding(severity: .medium), makeFinding(severity: .medium)]
        let (v2, s2) = engine.evaluate(findings: twoMedium)
        #expect(s2 == 30)
        #expect(v2 == .medium)

        // Score 35 -> High
        let medPlusHigh = [makeFinding(severity: .medium), makeFinding(severity: .medium), makeFinding(severity: .low)]
        let (v3, s3) = engine.evaluate(findings: medPlusHigh)
        #expect(s3 == 35)
        #expect(v3 == .high)
    }

    // MARK: - Helpers

    private func makeFinding(severity: Verdict) -> Finding {
        Finding(
            id: "test_\(severity.rawValue)",
            category: .heuristic,
            severity: severity,
            confidence: .high,
            summary: "Test finding",
            evidence: "Test evidence",
            location: nil,
            remediation: nil
        )
    }
}
