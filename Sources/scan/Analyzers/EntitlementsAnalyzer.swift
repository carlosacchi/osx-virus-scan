import Foundation
import Security

/// Extracts and evaluates code signing entitlements
struct EntitlementsAnalyzer: Analyzer, Sendable {
    let name = "entitlements"

    /// Entitlements considered dangerous with their severity and reason
    private static let dangerousEntitlements: [(key: String, severity: Verdict, reason: String)] = [
        ("com.apple.security.cs.disable-library-validation", .high,
         "Can load unsigned or differently-signed libraries"),
        ("com.apple.security.cs.allow-unsigned-executable-memory", .high,
         "Can map writable and executable memory (JIT)"),
        ("com.apple.security.cs.allow-dyld-environment-variables", .high,
         "DYLD_* environment variables honored (library injection risk)"),
        ("com.apple.security.cs.debugger", .high,
         "Can attach debugger to other processes"),
        ("com.apple.security.get-task-allow", .medium,
         "Allows task_for_pid (debug build, process inspection)"),
        ("com.apple.security.files.all", .medium,
         "Full disk access entitlement"),
        ("com.apple.security.automation.apple-events", .medium,
         "Can send Apple Events to control other applications"),
        ("com.apple.security.temporary-exception.files.absolute-path.read-write", .medium,
         "Temporary exception for file access"),
        ("com.apple.security.device.camera", .low,
         "Camera access"),
        ("com.apple.security.device.microphone", .low,
         "Microphone access"),
        ("com.apple.security.personal-information.location", .low,
         "Location access"),
        ("com.apple.security.personal-information.addressbook", .low,
         "Contacts access"),
        ("com.apple.security.personal-information.calendars", .low,
         "Calendar access"),
        ("com.apple.security.network.client", .info,
         "Outbound network connections"),
        ("com.apple.security.network.server", .low,
         "Inbound network connections (listening socket)"),
    ]

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        let analyzableTypes: [FileType] = [.machO, .app]
        return analyzableTypes.contains(context.metadata.fileType)
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        // Use Security.framework to extract entitlements
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(context.fileURL as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return findings
        }

        var info: CFDictionary?
        let infoFlags = SecCSFlags(rawValue: kSecCSSigningInformation)
        let infoStatus = SecCodeCopySigningInformation(code, infoFlags, &info)

        guard infoStatus == errSecSuccess, let dict = info as? [String: Any] else {
            return findings
        }

        // Extract entitlements dictionary
        guard let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            findings.append(Finding(
                id: "entitlements_none",
                category: .signature,
                severity: .info,
                confidence: .high,
                summary: "No entitlements found",
                evidence: "Binary has no embedded entitlements",
                location: nil,
                remediation: nil
            ))
            return findings
        }

        // Check for known dangerous entitlements
        for (key, severity, reason) in Self.dangerousEntitlements {
            if let value = entitlements[key] {
                let valueStr: String
                if let boolVal = value as? Bool {
                    valueStr = boolVal ? "true" : "false"
                } else {
                    valueStr = String(describing: value)
                }

                // Only flag if the entitlement is enabled (true)
                let isEnabled = (value as? Bool) == true || !(value is Bool)
                if isEnabled {
                    findings.append(Finding(
                        id: "entitlement_\(key.replacingOccurrences(of: ".", with: "_"))",
                        category: .signature,
                        severity: severity,
                        confidence: .high,
                        summary: "Entitlement: \(reason)",
                        evidence: "\(key) = \(valueStr)",
                        location: nil,
                        remediation: severity >= .medium
                            ? "This entitlement grants elevated privileges. Verify it is expected for this application."
                            : nil
                    ))
                }
            }
        }

        // Report total entitlement count
        if !entitlements.isEmpty {
            findings.append(Finding(
                id: "entitlements_summary",
                category: .signature,
                severity: .info,
                confidence: .high,
                summary: "\(entitlements.count) entitlement(s) found",
                evidence: entitlements.keys.sorted().joined(separator: ", "),
                location: nil,
                remediation: nil
            ))
        }

        return findings
    }
}
