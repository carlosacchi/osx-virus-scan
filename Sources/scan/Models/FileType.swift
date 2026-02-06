import Foundation

/// Detected file type based on extension and magic bytes
enum FileType: String, Codable, Sendable {
    case dmg
    case zip
    case pkg
    case app
    case machO = "macho"
    case plist
    case script
    case unknown

    /// Whether this type represents a container that should be unpacked
    var isContainer: Bool {
        switch self {
        case .dmg, .zip, .pkg: return true
        default: return false
        }
    }

    /// Human-readable display name
    var displayName: String {
        switch self {
        case .dmg: return "DMG"
        case .zip: return "ZIP"
        case .pkg: return "PKG"
        case .app: return "App Bundle"
        case .machO: return "Mach-O Binary"
        case .plist: return "Property List"
        case .script: return "Script"
        case .unknown: return "Unknown"
        }
    }
}
