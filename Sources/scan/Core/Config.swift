import Foundation

/// Persistent configuration for the scan tool
struct ScanConfig: Codable, Sendable {
    /// VirusTotal API key (optional, user-provided)
    var virusTotalAPIKey: String?
    /// YARA rules sources (URLs to download rules from)
    var yaraRuleSources: [String]
    /// Whether ClamAV integration is enabled
    var clamavEnabled: Bool
    /// Whether YARA integration is enabled
    var yaraEnabled: Bool

    static let `default` = ScanConfig(
        virusTotalAPIKey: nil,
        yaraRuleSources: [],
        clamavEnabled: true,
        yaraEnabled: true
    )

    /// Configuration directory path
    static var configDir: URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return home.appendingPathComponent(".config/scan")
    }

    /// Path to the config file
    static var configFile: URL {
        configDir.appendingPathComponent("config.json")
    }

    /// YARA rules directory
    static var yaraRulesDir: URL {
        configDir.appendingPathComponent("rules/yara")
    }

    /// Custom YARA rules directory
    static var yaraCustomRulesDir: URL {
        configDir.appendingPathComponent("rules/yara/custom")
    }

    /// ClamAV database directory
    static var clamavDBDir: URL {
        configDir.appendingPathComponent("clamav")
    }

    /// Load config from disk, or return defaults
    static func load() -> ScanConfig {
        guard let data = try? Data(contentsOf: configFile),
              let config = try? JSONDecoder().decode(ScanConfig.self, from: data) else {
            return .default
        }
        return config
    }

    /// Save config to disk
    func save() throws {
        try FileManager.default.createDirectory(
            at: ScanConfig.configDir,
            withIntermediateDirectories: true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        try data.write(to: ScanConfig.configFile)
    }

    /// Ensure all required directories exist
    static func ensureDirectories() throws {
        let dirs = [configDir, yaraRulesDir, yaraCustomRulesDir, clamavDBDir]
        for dir in dirs {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }
}
