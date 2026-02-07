import ArgumentParser
import Foundation

@main
struct ScanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Static file analyzer for macOS — pre-flight safety check",
        version: ToolInfo.current.version,
        subcommands: [ScanFileCommand.self, UpdateCommand.self, SetupCommand.self, ConfigCommand.self],
        defaultSubcommand: ScanFileCommand.self
    )
}
