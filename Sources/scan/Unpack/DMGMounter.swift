import Foundation

/// Mounts DMG files read-only and manages cleanup
final class DMGMounter: Unpacker, @unchecked Sendable {
    let supportedTypes: [FileType] = [.dmg]

    private let shell = ShellRunner()
    private let logger: VerboseLogger
    private var mountPoints: [String] = []

    init(logger: VerboseLogger) {
        self.logger = logger
    }

    func unpack(source: URL, into destination: URL) async throws -> UnpackResult {
        var findings: [Finding] = []

        logger.info("Mounting DMG: \(source.lastPathComponent)")

        // Mount DMG read-only with plist output for parsing
        let mountDir = destination.appendingPathComponent("dmg-mount")
        try FileManager.default.createDirectory(at: mountDir, withIntermediateDirectories: true)

        let result = try await shell.run(
            executable: "/usr/bin/hdiutil",
            arguments: [
                "attach",
                source.path,
                "-plist",
                "-readonly",
                "-nobrowse",
                "-noverify",
                "-noautoopen",
                "-mountrandom", mountDir.path
            ],
            timeout: 120
        )

        // Handle errors
        if !result.succeeded {
            // Check for encrypted DMG
            if result.stderr.contains("authenticate") || result.stderr.contains("password")
                || result.stderr.contains("encrypted") {
                throw ScanError.encryptedContainer(path: source.path)
            }
            throw ScanError.unpackFailed(
                type: .dmg,
                reason: "hdiutil attach failed (exit \(result.exitCode)): \(result.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }

        // Parse plist output to find mount point
        guard let plistData = result.stdout.data(using: .utf8) else {
            throw ScanError.unpackFailed(type: .dmg, reason: "Failed to parse hdiutil output")
        }

        let mountPoint = try parseMountPoint(from: plistData)
        mountPoints.append(mountPoint)

        logger.info("DMG mounted at: \(mountPoint)")

        // Check for multiple volumes (unusual, potentially suspicious)
        let allMountPoints = try parseAllMountPoints(from: plistData)
        if allMountPoints.count > 1 {
            findings.append(Finding(
                id: "dmg_multiple_volumes",
                category: .packaging,
                severity: .low,
                confidence: .high,
                summary: "DMG contains \(allMountPoints.count) volumes",
                evidence: "Mount points: \(allMountPoints.joined(separator: ", "))",
                location: nil,
                remediation: "Inspect each volume manually"
            ))
            // Track all mount points for cleanup
            for mp in allMountPoints where !mountPoints.contains(mp) {
                mountPoints.append(mp)
            }
        }

        return UnpackResult(
            contentRoot: URL(fileURLWithPath: mountPoint),
            findings: findings
        )
    }

    func cleanup() async {
        for mountPoint in mountPoints {
            logger.info("Unmounting: \(mountPoint)")
            do {
                let result = try await shell.run(
                    executable: "/usr/bin/hdiutil",
                    arguments: ["detach", mountPoint, "-force"],
                    timeout: 30
                )
                if !result.succeeded {
                    logger.error("Failed to unmount \(mountPoint): \(result.stderr)")
                }
            } catch {
                logger.error("Error unmounting \(mountPoint): \(error)")
            }
        }
        mountPoints.removeAll()
    }

    // MARK: - Plist parsing

    /// Parse the primary mount point from hdiutil plist output
    private func parseMountPoint(from data: Data) throws -> String {
        let allPoints = try parseAllMountPoints(from: data)
        guard let first = allPoints.first else {
            throw ScanError.unpackFailed(type: .dmg, reason: "No mount point found in hdiutil output")
        }
        return first
    }

    /// Parse all mount points from hdiutil plist output
    private func parseAllMountPoints(from data: Data) throws -> [String] {
        guard let plist = try PropertyListSerialization.propertyList(
            from: data, format: nil
        ) as? [String: Any],
        let entities = plist["system-entities"] as? [[String: Any]] else {
            throw ScanError.unpackFailed(type: .dmg, reason: "Unexpected hdiutil plist structure")
        }

        return entities.compactMap { entity in
            entity["mount-point"] as? String
        }
    }
}
