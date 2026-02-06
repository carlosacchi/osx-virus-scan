import Foundation
import os

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
    ///   - stdinData: Optional data to write to the process's stdin (prevents hanging on interactive prompts)
    ///   - timeout: Maximum execution time in seconds (default 60)
    /// - Returns: ShellResult with exit code, stdout, and stderr
    func run(
        executable: String,
        arguments: [String],
        stdinData: Data? = nil,
        timeout: TimeInterval = 60
    ) async throws -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        if let stdinData {
            let stdinPipe = Pipe()
            process.standardInput = stdinPipe
            try process.run()
            stdinPipe.fileHandleForWriting.write(stdinData)
            stdinPipe.fileHandleForWriting.closeFile()
        } else {
            process.standardInput = FileHandle.nullDevice
            try process.run()
        }

        // Read pipe data concurrently to avoid deadlock when output fills pipe buffers.
        // Must read BEFORE waitUntilExit(), otherwise large output blocks the child process.
        let stdoutHandle = stdoutPipe.fileHandleForReading
        let stderrHandle = stderrPipe.fileHandleForReading

        async let stdoutData = Task.detached { stdoutHandle.readDataToEndOfFile() }.value
        async let stderrData = Task.detached { stderrHandle.readDataToEndOfFile() }.value

        // Track whether we triggered the timeout (vs process killed by other signal).
        // OSAllocatedUnfairLock is Sendable, safe to share between Task and caller.
        let didTimeout = OSAllocatedUnfairLock(initialState: false)

        // Set up timeout
        let timeoutTask = Task {
            try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            if process.isRunning {
                didTimeout.withLock { $0 = true }
                process.terminate()
            }
        }

        // Collect pipe data and wait for process
        let outData = await stdoutData
        let errData = await stderrData
        process.waitUntilExit()
        timeoutTask.cancel()

        let stdout = String(data: outData, encoding: .utf8) ?? ""
        let stderr = String(data: errData, encoding: .utf8) ?? ""

        // Only throw timeout if we actually triggered termination
        if didTimeout.withLock({ $0 }) {
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
