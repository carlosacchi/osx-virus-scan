import Foundation

/// Registry that manages and runs all analyzers
struct AnalyzerRegistry: Sendable {
    private let analyzers: [any Analyzer]
    private let logger: VerboseLogger

    init(logger: VerboseLogger) {
        self.logger = logger
        self.analyzers = [
            // Stage 3: built-in static analysis
            CodeSignAnalyzer(),
            GatekeeperAnalyzer(),
            EntitlementsAnalyzer(),
            MachOAnalyzer(),
            PersistenceAnalyzer(),
            InstallerScriptAnalyzer(),
            // Stage 4: optional external detection engines
            ClamAVAnalyzer(),
            YaraAnalyzer(),
            ReputationAnalyzer(),
        ]
    }

    /// Run all applicable analyzers against the given context
    /// - Parameters:
    ///   - context: Analysis context with file info and options
    ///   - strict: If true, stop on first analyzer error
    /// - Returns: Tuple of findings and errors
    func runAll(context: AnalysisContext, strict: Bool) async -> ([Finding], [ScanErrorRecord]) {
        var allFindings: [Finding] = []
        var allErrors: [ScanErrorRecord] = []

        for analyzer in analyzers {
            guard analyzer.canAnalyze(context) else {
                logger.debug("Skipping \(analyzer.name): not applicable")
                continue
            }

            logger.info("Running analyzer: \(analyzer.name)")

            do {
                let findings = try await analyzer.analyze(context)
                allFindings.append(contentsOf: findings)
                logger.debug("\(analyzer.name): \(findings.count) findings")
            } catch {
                let errRecord = ScanErrorRecord(
                    step: "analyzer:\(analyzer.name)",
                    message: error.localizedDescription
                )
                allErrors.append(errRecord)
                logger.error("Analyzer '\(analyzer.name)' failed: \(error)")

                if strict {
                    break
                }
            }
        }

        return (allFindings, allErrors)
    }
}
