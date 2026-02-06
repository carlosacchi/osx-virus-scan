import ArgumentParser
import CryptoKit
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

    /// YARA rule sources with pinned SHA-256 for integrity verification.
    /// To update a rule: download the new file, compute its SHA-256, and update the hash here.
    /// Set sha256 to nil to skip verification (not recommended for production).
    private static let yaraRuleSources: [(name: String, url: String, sha256: String?)] = [
        ("MALW_Adwind", "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Adwind.yar",
         "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"),
        ("MALW_Eicar", "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar",
         "1ba3175cebe28fc5d4d25c1caf604beda152766db268a3f159e4bf61c2eddf54"),
    ]

    private func updateYARA(shell: ShellRunner, logger: VerboseLogger) async {
        let rulesDir = ScanConfig.yaraRulesDir

        // Check if yara is installed
        let yaraPaths = ["/opt/homebrew/bin/yara", "/usr/local/bin/yara"]
        guard yaraPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) != nil else {
            print("  YARA not installed. Install with: brew install yara")
            return
        }

        // Download bundled rule sources
        var downloaded = 0
        for source in Self.yaraRuleSources {
            let destFile = rulesDir.appendingPathComponent("\(source.name).yar")
            print("  Downloading \(source.name)...")
            do {
                let url = URL(string: source.url)!
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                    print("    Failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0))")
                    continue
                }

                // Verify integrity if a pinned hash is available
                if let expectedHash = source.sha256 {
                    let actualHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                    if actualHash != expectedHash {
                        print("    Integrity check FAILED — expected \(expectedHash.prefix(16))..., got \(actualHash.prefix(16))...")
                        print("    Skipping \(source.name) (possible tampering or upstream change)")
                        continue
                    }
                    print("    SHA-256 verified")
                }

                try data.write(to: destFile)
                downloaded += 1
            } catch {
                print("    Error: \(error.localizedDescription)")
            }
        }
        print("  Downloaded \(downloaded) rule file(s).")

        // Count total rules
        let existingRules = (try? FileManager.default.contentsOfDirectory(
            at: rulesDir, includingPropertiesForKeys: nil
        ))?.filter { $0.pathExtension == "yar" || $0.pathExtension == "yara" } ?? []

        print("  Rules directory: \(rulesDir.path) (\(existingRules.count) file(s))")
        print("  Custom rules: \(ScanConfig.yaraCustomRulesDir.path)")
        print("")
        print("  Additional rule sources:")
        print("    - https://github.com/Yara-Rules/rules")
        print("    - https://github.com/elastic/protections-artifacts")
        print("    - https://github.com/reversinglabs/reversinglabs-yara-rules")
    }
}
