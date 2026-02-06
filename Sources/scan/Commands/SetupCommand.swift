import ArgumentParser
import Foundation

struct SetupCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        abstract: "Install optional dependencies (ClamAV, YARA) and initialize databases"
    )

    @Flag(name: .long, help: "Only install ClamAV")
    var clamav = false

    @Flag(name: .long, help: "Only install YARA")
    var yara = false

    mutating func run() async throws {
        let shell = ShellRunner()
        let installAll = !clamav && !yara

        print("scan setup — Installing optional dependencies\n")

        // Check Homebrew is available
        let brewPath = try await findBrew(shell: shell)

        if installAll || clamav {
            await installClamAV(shell: shell, brewPath: brewPath)
            print("")
        }

        if installAll || yara {
            await installYARA(shell: shell, brewPath: brewPath)
            print("")
        }

        // Ensure config directories exist
        try ScanConfig.ensureDirectories()

        print("Setup complete. Run `scan update` to download the latest definitions.")
    }

    // MARK: - Homebrew

    private func findBrew(shell: ShellRunner) async throws -> String {
        let paths = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        if let path = paths.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            return path
        }
        print("Homebrew not found. Install it from https://brew.sh")
        throw ExitCode(2)
    }

    // MARK: - ClamAV

    private func installClamAV(shell: ShellRunner, brewPath: String) async {
        print("--- ClamAV ---")

        let clamPaths = ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"]
        if clamPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) != nil {
            print("  Already installed.")
            await initClamAV(shell: shell)
            return
        }

        print("  Installing clamav via Homebrew...")
        do {
            let result = try await shell.run(
                executable: brewPath,
                arguments: ["install", "clamav"],
                timeout: 300
            )
            if result.succeeded {
                print("  ClamAV installed successfully.")
                await initClamAV(shell: shell)
            } else {
                print("  Failed to install ClamAV: \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            print("  Error installing ClamAV: \(error.localizedDescription)")
        }
    }

    private func initClamAV(shell: ShellRunner) async {
        // Create freshclam.conf if it doesn't exist
        let confPaths = ["/opt/homebrew/etc/clamav/freshclam.conf", "/usr/local/etc/clamav/freshclam.conf"]
        let samplePaths = ["/opt/homebrew/etc/clamav/freshclam.conf.sample", "/usr/local/etc/clamav/freshclam.conf.sample"]

        for (conf, sample) in zip(confPaths, samplePaths) {
            if !FileManager.default.fileExists(atPath: conf),
               FileManager.default.fileExists(atPath: sample) {
                do {
                    var lines = try String(contentsOfFile: sample, encoding: .utf8)
                        .components(separatedBy: "\n")
                    // Comment out only standalone "Example" directives, not substrings
                    lines = lines.map { $0.trimmingCharacters(in: .whitespaces) == "Example" ? "# Example" : $0 }
                    let contents = lines.joined(separator: "\n")
                    try contents.write(toFile: conf, atomically: true, encoding: .utf8)
                    print("  Created freshclam.conf")
                } catch {
                    print("  Warning: could not create freshclam.conf: \(error.localizedDescription)")
                }
            }
        }

        // Run freshclam to download initial definitions
        let freshclamPaths = ["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam"]
        guard let freshclamPath = freshclamPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            return
        }

        print("  Downloading virus definitions (this may take a minute)...")
        do {
            let result = try await shell.run(
                executable: freshclamPath,
                arguments: [],
                timeout: 600
            )
            if result.succeeded {
                print("  Virus definitions downloaded.")
            } else {
                let err = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                if err.contains("up to date") || result.stdout.contains("up to date") {
                    print("  Virus definitions are up to date.")
                } else {
                    print("  freshclam warning: \(err)")
                }
            }
        } catch {
            print("  Error running freshclam: \(error.localizedDescription)")
        }
    }

    // MARK: - YARA

    private func installYARA(shell: ShellRunner, brewPath: String) async {
        print("--- YARA ---")

        let yaraPaths = ["/opt/homebrew/bin/yara", "/usr/local/bin/yara"]
        if yaraPaths.first(where: { FileManager.default.fileExists(atPath: $0) }) != nil {
            print("  Already installed.")
            return
        }

        print("  Installing yara via Homebrew...")
        do {
            let result = try await shell.run(
                executable: brewPath,
                arguments: ["install", "yara"],
                timeout: 300
            )
            if result.succeeded {
                print("  YARA installed successfully.")
                print("  Place rules in: \(ScanConfig.yaraRulesDir.path)")
            } else {
                print("  Failed to install YARA: \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            print("  Error installing YARA: \(error.localizedDescription)")
        }
    }
}
