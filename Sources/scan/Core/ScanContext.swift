import Foundation

/// Scan options derived from CLI flags
struct ScanOptions: Sendable {
    let json: Bool
    let verbose: Bool
    let debug: Bool
    let strict: Bool
    let offline: Bool
    let reputation: Bool
    let noCleanup: Bool
    let maxExecutableChecks: Int?  // nil = unlimited, default 20 for compat

    static let `default` = ScanOptions(
        json: false, verbose: false, debug: false,
        strict: false, offline: true, reputation: false, noCleanup: false,
        maxExecutableChecks: nil
    )
}
