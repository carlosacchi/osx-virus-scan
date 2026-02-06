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

        // Detach if this DMG is already mounted (prevents "Resource busy")
        await detachIfAlreadyMounted(source: source)

        // Mount DMG read-only with plist output for parsing
        let mountDir = destination.appendingPathComponent("dmg-mount")
        try FileManager.default.createDirectory(at: mountDir, withIntermediateDirectories: true)

        let result = try await attachWithRetry(source: source, mountDir: mountDir)

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

    // MARK: - Mount helpers

    /// Attempt hdiutil attach with retries for transient "Resource busy" errors
    private func attachWithRetry(source: URL, mountDir: URL, maxRetries: Int = 2) async throws -> ShellResult {
        var lastResult: ShellResult?

        for attempt in 0...maxRetries {
            if attempt > 0 {
                logger.info("Retrying DMG mount (attempt \(attempt + 1)/\(maxRetries + 1))...")
                try await Task.sleep(for: .seconds(2))
            }

            // Pipe "Y\n" to stdin to auto-accept EULA if the DMG has one
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
                stdinData: "Y\n".data(using: .utf8),
                timeout: 120
            )

            if result.succeeded {
                return result
            }

            lastResult = result

            // Check for encrypted DMG — no point retrying
            if result.stderr.contains("authenticate") || result.stderr.contains("password")
                || result.stderr.contains("encrypted") {
                throw ScanError.encryptedContainer(path: source.path)
            }

            // Only retry on "Resource busy"
            if !result.stderr.contains("Resource busy") {
                break
            }
        }

        let r = lastResult!
        let hint = r.stderr.contains("Resource busy")
            ? " (the file may be in use by another app — close torrent clients, Finder previews, etc.)"
            : ""
        throw ScanError.unpackFailed(
            type: .dmg,
            reason: "hdiutil attach failed (exit \(r.exitCode)): \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))\(hint)"
        )
    }

    // MARK: - Pre-mount checks

    /// Detach a DMG if it's already mounted (e.g. by Finder or a previous scan)
    private func detachIfAlreadyMounted(source: URL) async {
        do {
            let info = try await shell.run(
                executable: "/usr/bin/hdiutil",
                arguments: ["info", "-plist"],
                timeout: 15
            )
            guard info.succeeded,
                  let data = info.stdout.data(using: .utf8),
                  let plist = try PropertyListSerialization.propertyList(
                      from: data, format: nil
                  ) as? [String: Any],
                  let images = plist["images"] as? [[String: Any]]
            else { return }

            let sourcePath = source.path
            for image in images {
                guard let imagePath = image["image-path"] as? String,
                      imagePath == sourcePath,
                      let entities = image["system-entities"] as? [[String: Any]]
                else { continue }

                // Found a match — detach each mount point
                for entity in entities {
                    if let mp = entity["mount-point"] as? String {
                        logger.info("DMG already mounted at \(mp), detaching first")
                        let _ = try? await shell.run(
                            executable: "/usr/bin/hdiutil",
                            arguments: ["detach", mp, "-force"],
                            timeout: 30
                        )
                    }
                }
                // Also try detaching by dev-entry as fallback
                if let devEntry = entities.first?["dev-entry"] as? String {
                    let _ = try? await shell.run(
                        executable: "/usr/bin/hdiutil",
                        arguments: ["detach", devEntry, "-force"],
                        timeout: 30
                    )
                }
            }
        } catch {
            logger.info("Could not check for existing mounts: \(error)")
        }
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
