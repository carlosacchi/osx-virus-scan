import Foundation

/// Result of running a subprocess
struct ShellResult: Sendable {
    let exitCode: Int32
    let stdout: String
    let stderr: String

    var succeeded: Bool { exitCode == 0 }
}

/// Runs external commands with timeout and output capture
struct ShellRunner: Sendable {

    /// Run an executable with arguments
    /// - Parameters:
    ///   - executable: Full path to the executable (e.g., "/usr/bin/hdiutil")
    ///   - arguments: Command arguments
    ///   - timeout: Maximum execution time in seconds (default 60)
    /// - Returns: ShellResult with exit code, stdout, and stderr
    func run(
        executable: String,
        arguments: [String],
        timeout: TimeInterval = 60
    ) async throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        try process.run()

        // Set up timeout
        let timeoutTask = Task {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if process.isRunning {
                process.terminate()
            }
        }

        process.waitUntilExit()
        timeoutTask.cancel()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""

        // Check if process was terminated due to timeout
        if process.terminationReason == .uncaughtSignal {
            throw ScanError.subprocessTimeout(
                command: "\(executable) \(arguments.joined(separator: " "))",
                timeout: timeout
            )
        }

        return ShellResult(
            exitCode: process.terminationStatus,
            stdout: stdout,
            stderr: stderr
        )
    }
}
