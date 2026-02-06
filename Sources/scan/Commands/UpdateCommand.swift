import ArgumentParser
import Foundation

struct UpdateCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "update",
        abstract: "Update detection rules and databases"
    )

    @Flag(name: .long, help: "Only update ClamAV database")
    var clamav = false

    @Flag(name: .long, help: "Only update YARA rules")
    var yara = false

    mutating func run() async throws {
        let logger = VerboseLogger(verbose: true, debug: false)
        let shell = ShellRunner()
        let updateAll = !clamav && !yara

        // Ensure directories exist
        try ScanConfig.ensureDirectories()

        print("scan update — Updating detection databases\n")

        // Update ClamAV
        if updateAll || clamav {
            print("--- ClamAV ---")
            await updateClamAV(shell: shell, logger: logger)
            print("")
        }

        // Update YARA rules
        if updateAll || yara {
            print("--- YARA Rules ---")
            await updateYARA(shell: shell, logger: logger)
            print("")
        }

        print("Update complete.")
    }

    private func updateClamAV(shell: ShellRunner, logger: VerboseLogger) async {
        // Find freshclam
        let freshclamPaths = ["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam"]
        guard let freshclamPath = freshclamPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            print("  ClamAV not installed. Install with: brew install clamav")
            print("  Then run: freshclam (to download initial database)")
            return
        }

        print("  Running freshclam to update virus definitions...")

        do {
            let result = try await shell.run(
                executable: freshclamPath,
                arguments: [],
                timeout: 300
            )

            if result.succeeded {
                print("  ClamAV database updated successfully.")
                if !result.stdout.isEmpty {
                    // Extract key info from freshclam output
                    let lines = result.stdout.components(separatedBy: "\n")
                    for line in lines where line.contains("updated") || line.contains("is up to date") {
                        print("  \(line.trimmingCharacters(in: .whitespaces))")
                    }
                }
            } else {
                print("  freshclam failed (exit \(result.exitCode))")
                if !result.stderr.isEmpty {
                    print("  \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
                }
                print("  Tip: You may need to create /opt/homebrew/etc/clamav/freshclam.conf first.")
            }
        } catch {
            print("  Error running freshclam: \(error.localizedDescription)")
        }
    }

    private func updateYARA(shell: ShellRunner, logger: VerboseLogger) async {
        let rulesDir = ScanConfig.yaraRulesDir

        // Check if yara is installed
        let yaraPaths = ["/opt/homebrew/bin/yara", "/usr/local/bin/yara"]
        guard yaraPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) != nil else {
            print("  YARA not installed. Install with: brew install yara")
            return
        }

        // Count existing rules
        let existingRules = (try? FileManager.default.contentsOfDirectory(
            at: rulesDir, includingPropertiesForKeys: nil
        ))?.filter { $0.pathExtension == "yar" || $0.pathExtension == "yara" } ?? []

        print("  Rules directory: \(rulesDir.path)")
        print("  Existing rules: \(existingRules.count) file(s)")
        print("  Custom rules directory: \(ScanConfig.yaraCustomRulesDir.path)")
        print("")
        print("  To add rules manually:")
        print("    - Place .yar/.yara files in: \(rulesDir.path)")
        print("    - Or for custom rules: \(ScanConfig.yaraCustomRulesDir.path)")
        print("")
        print("  Recommended rule sources:")
        print("    - https://github.com/Yara-Rules/rules")
        print("    - https://github.com/elastic/protections-artifacts")
        print("    - https://github.com/reversinglabs/reversinglabs-yara-rules")
    }
}
