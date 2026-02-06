import Foundation

/// Persistent configuration for the scan tool
struct ScanConfig: Codable, Sendable {
    /// VirusTotal API key (optional, user-provided)
    var virusTotalAPIKey: String?
    /// YARA rules sources (URLs to download rules from)
    var yaraRuleSources: [String]
    static let `default` = ScanConfig(
        virusTotalAPIKey: nil,
        yaraRuleSources: []
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
        // Restrict permissions to owner-only (may contain API keys)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: ScanConfig.configFile.path
        )
    }

    /// Ensure all required directories exist
    static func ensureDirectories() throws {
        let dirs = [configDir, yaraRulesDir, yaraCustomRulesDir, clamavDBDir]
        for dir in dirs {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
    }
}
