import Foundation

/// Overall scan verdict indicating risk level
enum Verdict: String, Codable, Sendable, CaseIterable {
    case info = "Info"
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case unknown = "Unknown"
    case error = "Error"
}

extension Verdict: Comparable {
    private var sortOrder: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .unknown: return 2
        case .medium: return 3
        case .high: return 4
        case .error: return 5
        }
    }

    static func < (lhs: Verdict, rhs: Verdict) -> Bool {
        lhs.sortOrder < rhs.sortOrder
    }
}
