import Foundation

/// Protocol for formatting scan results
protocol OutputFormatter: Sendable {
    func format(_ result: ScanResult) -> String
}
