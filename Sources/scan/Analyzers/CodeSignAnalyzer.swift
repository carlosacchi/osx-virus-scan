import Foundation
import Security

/// Verifies code signatures using Security.framework (SecStaticCode)
struct CodeSignAnalyzer: Analyzer, Sendable {
    let name = "codesign"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        let analyzableTypes: [FileType] = [.machO, .app, .dmg, .pkg]
        return analyzableTypes.contains(context.metadata.fileType)
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        // Try Security.framework API first
        let apiFindings = analyzeViaAPI(url: context.fileURL)
        findings.append(contentsOf: apiFindings)

        // If it's a container with extracted contents, also check inner executables
        if let manifest = context.manifest, let contentRoot = context.contentRoot {
            let executableEntries = manifest.entries.filter {
                $0.isExecutable || $0.type == .machO || $0.type == .app
            }

            for entry in executableEntries.prefix(20) { // Limit to avoid excessive checks
                let entryURL = contentRoot.appendingPathComponent(entry.relativePath)
                let entryFindings = analyzeViaAPI(url: entryURL)
                // Tag findings with location
                for finding in entryFindings {
                    findings.append(Finding(
                        id: finding.id,
                        category: finding.category,
                        severity: finding.severity,
                        confidence: finding.confidence,
                        summary: finding.summary,
                        evidence: finding.evidence,
                        location: entry.relativePath,
                        remediation: finding.remediation
                    ))
                }
            }
        }

        return findings
    }

    // MARK: - Security.framework API

    private func analyzeViaAPI(url: URL) -> [Finding] {
        var findings: [Finding] = []

        // Create static code reference
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)

        guard createStatus == errSecSuccess, let code = staticCode else {
            // Not a signable object (e.g., plain text file) — not an error
            if createStatus == errSecCSBadObjectFormat {
                return findings
            }
            findings.append(Finding(
                id: "codesign_no_code_object",
                category: .signature,
                severity: .info,
                confidence: .high,
                summary: "Cannot create code signature object",
                evidence: "SecStaticCodeCreateWithPath returned OSStatus \(createStatus)",
                location: nil,
                remediation: nil
            ))
            return findings
        }

        // Verify signature validity
        let verifyStatus = SecStaticCodeCheckValidity(code, [], nil)

        switch verifyStatus {
        case errSecSuccess:
            // Valid signature — extract details
            let infoFindings = extractSigningInfo(code: code)
            findings.append(contentsOf: infoFindings)

        case errSecCSUnsigned:
            findings.append(Finding(
                id: "codesign_unsigned",
                category: .signature,
                severity: .high,
                confidence: .high,
                summary: "Binary is not code signed",
                evidence: "No code signature found",
                location: nil,
                remediation: "Unsigned binaries bypass Gatekeeper. Verify the source before running."
            ))

        case errSecCSSignatureFailed:
            findings.append(Finding(
                id: "codesign_invalid",
                category: .signature,
                severity: .high,
                confidence: .high,
                summary: "Code signature is invalid",
                evidence: "Signature verification failed (seal broken or tampered)",
                location: nil,
                remediation: "The binary may have been modified after signing. Do not trust it."
            ))

        case errSecCSReqFailed:
            findings.append(Finding(
                id: "codesign_req_failed",
                category: .signature,
                severity: .medium,
                confidence: .high,
                summary: "Code signature requirements not met",
                evidence: "SecStaticCodeCheckValidity returned errSecCSReqFailed",
                location: nil,
                remediation: "The binary's designated requirement is not satisfied."
            ))

        default:
            let message = SecCopyErrorMessageString(verifyStatus, nil) as String? ?? "unknown"
            findings.append(Finding(
                id: "codesign_error",
                category: .signature,
                severity: .medium,
                confidence: .medium,
                summary: "Code signature check returned error",
                evidence: "OSStatus \(verifyStatus): \(message)",
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }

    /// Extract signing information (team ID, ad-hoc, identifier)
    private func extractSigningInfo(code: SecStaticCode) -> [Finding] {
        var findings: [Finding] = []

        var info: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)

        guard infoStatus == errSecSuccess, let dict = info as? [String: Any] else {
            return findings
        }

        // Team ID
        let teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
        let identifier = dict[kSecCodeInfoIdentifier as String] as? String

        // Check flags
        let flags = dict[kSecCodeInfoFlags as String] as? UInt32 ?? 0

        // Ad-hoc signature (kSecCodeSignatureAdhoc = 0x0002)
        let isAdhoc = flags & 0x0002 != 0
        if isAdhoc {
            findings.append(Finding(
                id: "codesign_adhoc",
                category: .signature,
                severity: .medium,
                confidence: .high,
                summary: "Binary has an ad-hoc signature",
                evidence: "Ad-hoc signatures are not tied to a developer identity" +
                    (identifier.map { ". Identifier: \($0)" } ?? ""),
                location: nil,
                remediation: "Ad-hoc signed binaries are not verified by Apple. Confirm the source."
            ))
        } else {
            // Properly signed
            var evidence = "Valid code signature"
            if let tid = teamID { evidence += ", Team ID: \(tid)" }
            if let id = identifier { evidence += ", Identifier: \(id)" }

            findings.append(Finding(
                id: "codesign_valid",
                category: .signature,
                severity: .info,
                confidence: .high,
                summary: "Binary is properly code signed",
                evidence: evidence,
                location: nil,
                remediation: nil
            ))
        }

        // Hardened runtime check (kSecCodeSignatureRuntime = 0x10000)
        let hasHardenedRuntime = flags & 0x10000 != 0
        if !hasHardenedRuntime && !isAdhoc {
            findings.append(Finding(
                id: "codesign_no_hardened_runtime",
                category: .signature,
                severity: .low,
                confidence: .high,
                summary: "Binary does not use hardened runtime",
                evidence: "Hardened runtime flag (0x10000) not set in code signature flags",
                location: nil,
                remediation: "Hardened runtime provides additional security protections. Its absence may indicate older or less security-conscious software."
            ))
        }

        return findings
    }
}
