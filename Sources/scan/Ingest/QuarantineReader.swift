import Foundation

/// Reads the com.apple.quarantine extended attribute from a file
struct QuarantineReader: Sendable {

    /// Read quarantine information from the given URL
    /// Returns nil if the file has no quarantine attribute
    func read(url: URL) -> QuarantineInfo? {
        // Try reading via xattr directly (more reliable than URL resource values
        // for the quarantine attribute raw value)
        return readViaXattr(path: url.path)
    }

    /// Read quarantine attribute using getxattr system call
    private func readViaXattr(path: String) -> QuarantineInfo? {
        let attrName = "com.apple.quarantine"

        // Get attribute size
        let size = getxattr(path, attrName, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }

        // Read attribute value
        var buffer = [UInt8](repeating: 0, count: size)
        let bytesRead = getxattr(path, attrName, &buffer, size, 0, XATTR_NOFOLLOW)
        guard bytesRead > 0 else { return nil }

        let rawValue = String(bytes: buffer.prefix(bytesRead), encoding: .utf8) ?? ""
        return parseQuarantineValue(rawValue)
    }

    /// Parse quarantine attribute value
    /// Format: flags;timestamp;agentBundleID;UUID
    /// Example: 0083;6543210a;Chrome;12345678-1234-1234-1234-123456789012
    private func parseQuarantineValue(_ raw: String) -> QuarantineInfo {
        let components = raw.split(separator: ";", maxSplits: 3, omittingEmptySubsequences: false)

        var agentName: String?
        let originURL: String? = nil
        var timestamp: Date?

        // Component 1: hex timestamp (seconds since 2001-01-01, Mac epoch)
        if components.count > 1, let hexTimestamp = UInt64(components[1], radix: 16) {
            // Mac absolute time epoch is 2001-01-01
            timestamp = Date(timeIntervalSinceReferenceDate: TimeInterval(hexTimestamp))
        }

        // Component 2: agent bundle ID or name
        if components.count > 2 {
            let agent = String(components[2])
            if !agent.isEmpty {
                agentName = agent
            }
        }

        // Note: origin URL may be stored in a companion attribute
        // (com.apple.quarantine doesn't always contain the URL directly;
        // the URL is sometimes in the LSQuarantineEvent database)

        return QuarantineInfo(
            agentName: agentName,
            originURL: originURL,
            timestamp: timestamp,
            rawValue: raw
        )
    }
}
