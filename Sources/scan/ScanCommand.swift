import ArgumentParser
import Foundation

@main
struct ScanCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "scan",
        abstract: "Static file analyzer for macOS — pre-flight safety check",
        version: "0.3.0",
        subcommands: [ScanFileCommand.self, UpdateCommand.self, SetupCommand.self],
        defaultSubcommand: ScanFileCommand.self
    )
}
