import Foundation

/// Information from the com.apple.quarantine extended attribute
struct QuarantineInfo: Codable, Sendable {
    /// Application that downloaded the file (e.g., "Chrome", "Safari")
    let agentName: String?
    /// URL the file was downloaded from
    let originURL: String?
    /// When the file was quarantined
    let timestamp: Date?
    /// Raw attribute value
    let rawValue: String
}
