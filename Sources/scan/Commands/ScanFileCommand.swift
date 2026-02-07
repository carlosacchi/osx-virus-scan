import ArgumentParser
import Foundation

struct ScanFileCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "file",
        abstract: "Scan a single file for security indicators"
    )

    @Argument(help: "Path to the file to scan")
    var path: String?

    @Option(name: .shortAndLong, help: "Path to the file to scan")
    var file: String?

    @Flag(name: .long, help: "Output results as JSON")
    var json = false

    @Flag(name: .long, help: "Enable verbose logging")
    var verbose = false

    @Flag(name: .long, help: "Enable debug logging")
    var debug = false

    @Flag(name: .long, help: "Fail if any check encounters an error")
    var strict = false

    @Flag(name: .long, inversion: .prefixedNo, help: "Force offline mode (no network calls)")
    var offline = true

    @Flag(name: .long, help: "Enable hash reputation lookup (requires network)")
    var reputation = false

    @Flag(name: .long, inversion: .prefixedNo, help: "Cleanup temporary files after scan")
    var cleanup = true

    @Option(name: .long, help: "Maximum executables to analyze (0 = unlimited)")
    var maxExecutableChecks: Int = 0  // 0 = unlimited by default

    @Flag(name: .long, help: "Enable hardened security checks (strict + reputation + verbose + no-offline)")
    var hardened = false

    mutating func validate() throws {
        guard file != nil || path != nil else {
            throw ValidationError("Please provide a file path: scan <path> or scan file -f <path>")
        }
    }

    mutating func run() async throws {
        let targetPath = file ?? path!

        let options = ScanOptions(
            json: json,
            verbose: verbose || debug || hardened,
            debug: debug,
            strict: strict || hardened,
            offline: offline && !hardened,  // disable offline if hardened
            reputation: reputation || hardened,
            noCleanup: !cleanup,
            maxExecutableChecks: maxExecutableChecks == 0 ? nil : maxExecutableChecks
        )

        let logger = VerboseLogger(verbose: options.verbose, debug: options.debug)
        let pipeline = Pipeline(options: options, logger: logger)

        do {
            let result = try await pipeline.run(path: targetPath)

            if json {
                let formatter = JSONOutputFormatter()
                print(formatter.format(result))
            } else {
                let formatter = TextFormatter()
                print(formatter.format(result))
            }

            // Exit with appropriate code based on verdict
            switch result.verdict {
            case .medium, .high:
                throw ExitCode(1)
            case .error:
                throw ExitCode(2)
            default:
                break
            }
        } catch let error as ScanError {
            logger.error(error.description)
            if json {
                let errorResult = ScanResult(
                    tool: .current,
                    timestamp: ISO8601DateFormatter().string(from: Date()),
                    input: InputInfo(path: targetPath, type: .unknown),
                    verdict: .error,
                    score: 0,
                    metadata: FileMetadata(
                        path: targetPath, resolvedPath: targetPath, isSymlink: false,
                        sha256: "", sizeBytes: 0, fileType: .unknown,
                        quarantine: nil, permissions: ""
                    ),
                    manifest: nil,
                    findings: [],
                    errors: [ScanErrorRecord(step: "scan", message: error.description)],
                    scanDuration: 0,
                    coverage: AnalysisCoverage(
                        totalAnalyzers: 0,
                        applicableAnalyzers: 0,
                        analyzersRun: [],
                        findingsBySeverity: [:],
                        categoriesCovered: [],
                        executionTime: 0
                    )
                )
                let formatter = JSONOutputFormatter()
                print(formatter.format(errorResult))
            } else {
                print("Error: \(error.description)")
            }
            throw ExitCode(2)
        }
    }
}
