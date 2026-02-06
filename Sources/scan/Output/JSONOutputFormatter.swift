import Foundation

/// Formats scan results as JSON
struct JSONOutputFormatter: OutputFormatter, Sendable {

    func format(_ result: ScanResult) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        guard let data = try? encoder.encode(result),
              let json = String(data: data, encoding: .utf8) else {
            return "{\"error\": \"Failed to encode scan result\"}"
        }
        return json
    }
}
