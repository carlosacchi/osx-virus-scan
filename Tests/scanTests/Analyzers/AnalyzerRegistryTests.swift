import Testing
import Foundation
@testable import scan

/// A stub analyzer that always throws
struct FailingAnalyzer: Analyzer, Sendable {
    let name = "failing_test"

    func canAnalyze(_ context: AnalysisContext) -> Bool { true }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        throw ScanError.analyzerFailed(name: name, reason: "intentional test failure")
    }
}

/// A stub analyzer that always succeeds with one finding
struct SucceedingAnalyzer: Analyzer, Sendable {
    let name = "succeeding_test"

    func canAnalyze(_ context: AnalysisContext) -> Bool { true }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        [Finding(
            id: "test_ok",
            category: .signature,
            severity: .info,
            confidence: .high,
            summary: "Test passed",
            evidence: "n/a",
            location: nil,
            remediation: nil
        )]
    }
}

@Suite("AnalyzerRegistry Tests")
struct AnalyzerRegistryTests {

    private func makeContext() -> AnalysisContext {
        let metadata = FileMetadata(
            path: "/bin/ls",
            resolvedPath: "/bin/ls",
            isSymlink: false,
            sha256: "abc",
            sizeBytes: 100,
            fileType: .machO,
            quarantine: nil,
            permissions: "rwxr-xr-x"
        )
        return AnalysisContext(
            metadata: metadata,
            fileURL: URL(fileURLWithPath: "/bin/ls"),
            contentRoot: nil,
            manifest: nil,
            options: .default,
            logger: VerboseLogger(verbose: false, debug: false)
        )
    }

    @Test("Strict mode throws on analyzer failure")
    func strictModeThrows() async {
        let registry = AnalyzerRegistry(
            analyzers: [SucceedingAnalyzer(), FailingAnalyzer()],
            logger: VerboseLogger(verbose: false, debug: false)
        )
        let context = makeContext()

        await #expect(throws: ScanError.self) {
            _ = try await registry.runAll(context: context, strict: true)
        }
    }

    @Test("Non-strict mode collects errors without throwing")
    func nonStrictCollectsErrors() async throws {
        let registry = AnalyzerRegistry(
            analyzers: [SucceedingAnalyzer(), FailingAnalyzer()],
            logger: VerboseLogger(verbose: false, debug: false)
        )
        let context = makeContext()

        let (findings, errors) = try await registry.runAll(context: context, strict: false)
        #expect(findings.count == 1)
        #expect(errors.count == 1)
        #expect(errors[0].step == "analyzer:failing_test")
    }
}
