import Foundation

/// Main scan pipeline: ingest -> unpack -> analyze -> score -> output
struct Pipeline: Sendable {
    let options: ScanOptions
    let logger: VerboseLogger

    func run(path: String) async throws -> ScanResult {
        let startTime = Date()
        var findings: [Finding] = []
        var errors: [ScanErrorRecord] = []

        logger.info("Starting scan of: \(path)")

        // 1. Ingest: validate path, resolve symlinks, get basic attributes
        logger.debug("Phase: ingest")
        let ingestor = FileIngestor()
        let ingestResult = try ingestor.ingest(path: path)

        // Detect file type
        let detector = FileTypeDetector()
        let fileType: FileType

        if ingestResult.isDirectory {
            let dirType = detector.detect(url: ingestResult.resolvedURL)
            if dirType == .app {
                fileType = .app
            } else {
                throw ScanError.notAFile(path: ingestResult.resolvedURL.path)
            }
        } else {
            fileType = detector.detect(url: ingestResult.resolvedURL)
        }

        logger.info("Detected type: \(fileType.displayName)")

        // 2. Compute SHA-256 hash (streaming)
        logger.debug("Phase: hash")
        var sha256 = ""
        if !ingestResult.isDirectory {
            do {
                sha256 = try HashCalculator().sha256(of: ingestResult.resolvedURL)
                logger.info("SHA-256: \(sha256)")
            } catch {
                let errMsg = "Hash calculation failed: \(error.localizedDescription)"
                logger.error(errMsg)
                errors.append(ScanErrorRecord(step: "hash", message: errMsg))
                if options.strict {
                    throw ScanError.hashFailed(
                        path: ingestResult.resolvedURL.path,
                        reason: error.localizedDescription
                    )
                }
            }
        }

        // 3. Read quarantine attribute
        logger.debug("Phase: quarantine")
        let quarantine = QuarantineReader().read(url: ingestResult.resolvedURL)
        if quarantine != nil {
            logger.info("Quarantine attribute found")
        }

        // 4. Build metadata
        let metadata = FileMetadata(
            path: ingestResult.originalPath,
            resolvedPath: ingestResult.resolvedURL.path,
            isSymlink: ingestResult.isSymlink,
            sha256: sha256,
            sizeBytes: ingestResult.size,
            fileType: fileType,
            quarantine: quarantine,
            permissions: ingestResult.permissions
        )

        // 5. Unpack containers (DMG, ZIP, PKG)
        var manifest: Manifest?
        var unpacker: (any Unpacker)?
        var tempDir: TempDirectory?

        if fileType.isContainer {
            logger.debug("Phase: unpack")
            let td = try TempDirectory()
            tempDir = td

            do {
                let unpackerInstance = createUnpacker(for: fileType)
                unpacker = unpackerInstance

                let unpackResult = try await unpackerInstance.unpack(
                    source: ingestResult.resolvedURL,
                    into: td.url
                )
                findings.append(contentsOf: unpackResult.findings)

                // Generate manifest
                logger.debug("Phase: manifest")
                let manifestGen = ManifestGenerator(logger: logger)
                manifest = try manifestGen.generate(rootURL: unpackResult.contentRoot)

            } catch let error as ScanError {
                let errMsg = error.description
                logger.error(errMsg)
                errors.append(ScanErrorRecord(step: "unpack", message: errMsg))

                if options.strict {
                    await unpacker?.cleanup()
                    if !options.noCleanup { td.cleanup() }
                    throw error
                }
            } catch {
                let errMsg = "Unpack failed: \(error.localizedDescription)"
                logger.error(errMsg)
                errors.append(ScanErrorRecord(step: "unpack", message: errMsg))
                if options.strict {
                    await unpacker?.cleanup()
                    if !options.noCleanup { td.cleanup() }
                    throw ScanError.unpackFailed(type: fileType, reason: error.localizedDescription)
                }
            }
        }

        // Deferred cleanup
        defer {
            if let up = unpacker, let td = tempDir {
                let noCleanup = options.noCleanup
                Task {
                    await up.cleanup()
                    if !noCleanup { td.cleanup() }
                }
            }
        }

        // 6. Run analyzers
        logger.debug("Phase: analyze")

        // Track the content root for containers (where the DMG mount point or extraction dir may be)
        var contentRoot: URL?
        if fileType.isContainer, let td = tempDir {
            // The content root is the first subdirectory in the temp dir
            if let contents = try? FileManager.default.contentsOfDirectory(
                at: td.url, includingPropertiesForKeys: nil
            ) {
                // Find the mount/extract directory
                for item in contents {
                    var isDir: ObjCBool = false
                    if FileManager.default.fileExists(atPath: item.path, isDirectory: &isDir), isDir.boolValue {
                        contentRoot = item
                        break
                    }
                }
            }
        }

        let analysisContext = AnalysisContext(
            metadata: metadata,
            fileURL: ingestResult.resolvedURL,
            contentRoot: contentRoot,
            manifest: manifest,
            options: options,
            logger: logger
        )

        let registry = AnalyzerRegistry(logger: logger)
        let (analyzerFindings, analyzerErrors) = await registry.runAll(
            context: analysisContext,
            strict: options.strict
        )
        findings.append(contentsOf: analyzerFindings)
        errors.append(contentsOf: analyzerErrors)

        // 7. Score
        logger.debug("Phase: scoring")
        let scoring = ScoringEngine()
        let (verdict, score) = scoring.evaluate(findings: findings)

        logger.info("Verdict: \(verdict.rawValue), Score: \(score)")

        // 8. Build result
        let elapsed = Date().timeIntervalSince(startTime)

        return ScanResult(
            tool: .current,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            input: InputInfo(path: path, type: fileType),
            verdict: verdict,
            score: score,
            metadata: metadata,
            manifest: manifest,
            findings: findings,
            errors: errors,
            scanDuration: elapsed
        )
    }

    /// Create the appropriate unpacker for a file type
    private func createUnpacker(for type: FileType) -> any Unpacker {
        switch type {
        case .dmg: return DMGMounter(logger: logger)
        case .zip: return ZIPExtractor(logger: logger)
        case .pkg: return PKGInspector(logger: logger)
        default: fatalError("No unpacker for type: \(type)")
        }
    }
}
