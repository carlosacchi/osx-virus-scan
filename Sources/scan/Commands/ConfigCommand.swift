import ArgumentParser
import Foundation

struct ConfigCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Configure scan settings"
    )

    @Argument(help: "Configuration key (virustotal-key)")
    var key: String

    @Argument(help: "Configuration value")
    var value: String

    func run() async throws {
        var config = try ScanConfig.load()

        switch key {
        case "virustotal-key":
            config.virusTotalAPIKey = value
            try config.save()
            print("VirusTotal API key saved to \(ScanConfig.configFile.path)")
        default:
            throw ValidationError("Unknown config key: \(key). Valid keys: virustotal-key")
        }
    }
}
