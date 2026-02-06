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
        let applicable = analyzers.filter { $0.canAnalyze(context) }
        for a in analyzers where !applicable.contains(where: { $0.name == a.name }) {
            logger.debug("Skipping \(a.name): not applicable")
        }

        // Run analyzers in parallel using structured concurrency
        let results = await withTaskGroup(
            of: (String, Result<[Finding], Error>).self,
            returning: [(String, Result<[Finding], Error>)].self
        ) { group in
            for analyzer in applicable {
                group.addTask {
                    do {
                        let findings = try await analyzer.analyze(context)
                        return (analyzer.name, .success(findings))
                    } catch {
                        return (analyzer.name, .failure(error))
                    }
                }
            }
            var collected: [(String, Result<[Finding], Error>)] = []
            for await result in group {
                collected.append(result)
            }
            return collected
        }

        // Reassemble in original order for deterministic output
        var allFindings: [Finding] = []
        var allErrors: [ScanErrorRecord] = []

        for analyzer in applicable {
            guard let (_, result) = results.first(where: { $0.0 == analyzer.name }) else { continue }
            switch result {
            case .success(let findings):
                allFindings.append(contentsOf: findings)
                logger.debug("\(analyzer.name): \(findings.count) findings")
            case .failure(let error):
                allErrors.append(ScanErrorRecord(
                    step: "analyzer:\(analyzer.name)",
                    message: error.localizedDescription
                ))
                logger.error("Analyzer '\(analyzer.name)' failed: \(error)")
            }
        }

        return (allFindings, allErrors)
    }
}
