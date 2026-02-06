import Foundation

/// Optional hash reputation lookup — opt-in via --reputation flag
struct ReputationAnalyzer: Analyzer, Sendable {
    let name = "reputation"

    func canAnalyze(_ context: AnalysisContext) -> Bool {
        // Only run when --reputation flag is set and not in offline mode
        return context.options.reputation && !context.options.offline && !context.metadata.sha256.isEmpty
    }

    func analyze(_ context: AnalysisContext) async throws -> [Finding] {
        var findings: [Finding] = []

        let sha256 = context.metadata.sha256

        // Try MalwareBazaar first (free, no API key needed)
        let bazaarFindings = try await queryMalwareBazaar(sha256: sha256, logger: context.logger)
        findings.append(contentsOf: bazaarFindings)

        return findings
    }

    // MARK: - MalwareBazaar API

    /// Query MalwareBazaar for hash reputation
    private func queryMalwareBazaar(sha256: String, logger: VerboseLogger) async throws -> [Finding] {
        var findings: [Finding] = []

        let url = URL(string: "https://mb-api.abuse.ch/api/v1/")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15

        let body = "query=get_info&hash=\(sha256)"
        request.httpBody = body.data(using: .utf8)

        logger.info("Querying MalwareBazaar for SHA-256: \(sha256)")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw ScanError.networkError(reason: "Invalid response from MalwareBazaar")
            }

            if httpResponse.statusCode == 429 {
                findings.append(Finding(
                    id: "reputation_rate_limited",
                    category: .reputation,
                    severity: .info,
                    confidence: .high,
                    summary: "Reputation lookup rate limited",
                    evidence: "MalwareBazaar returned HTTP 429",
                    location: nil,
                    remediation: "Wait and retry later."
                ))
                return findings
            }

            guard httpResponse.statusCode == 200 else {
                throw ScanError.networkError(reason: "MalwareBazaar returned HTTP \(httpResponse.statusCode)")
            }

            // Parse JSON response
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let queryStatus = json["query_status"] as? String else {
                return findings
            }

            switch queryStatus {
            case "hash_not_found", "no_results":
                findings.append(Finding(
                    id: "reputation_clean",
                    category: .reputation,
                    severity: .info,
                    confidence: .medium,
                    summary: "Hash not found in MalwareBazaar",
                    evidence: "SHA-256 \(sha256) is not in the MalwareBazaar database",
                    location: nil,
                    remediation: nil
                ))

            case "ok":
                // Known malware
                if let dataArray = json["data"] as? [[String: Any]], let first = dataArray.first {
                    let signature = first["signature"] as? String ?? "Unknown"
                    let fileName = first["file_name"] as? String ?? "Unknown"
                    let fileType = first["file_type_mime"] as? String ?? "Unknown"
                    let firstSeen = first["first_seen"] as? String ?? "Unknown"
                    let tags = (first["tags"] as? [String])?.joined(separator: ", ") ?? ""

                    findings.append(Finding(
                        id: "reputation_malware_bazaar",
                        category: .reputation,
                        severity: .high,
                        confidence: .high,
                        summary: "Known malware: \(signature)",
                        evidence: "MalwareBazaar match — Signature: \(signature), File: \(fileName), Type: \(fileType), First seen: \(firstSeen)" +
                            (tags.isEmpty ? "" : ", Tags: \(tags)"),
                        location: nil,
                        remediation: "This file matches a known malware sample in MalwareBazaar. Do NOT execute it."
                    ))
                }

            default:
                break
            }

        } catch let error as ScanError {
            throw error
        } catch {
            findings.append(Finding(
                id: "reputation_error",
                category: .reputation,
                severity: .info,
                confidence: .low,
                summary: "Reputation lookup failed",
                evidence: "Error: \(error.localizedDescription)",
                location: nil,
                remediation: "Check your network connection and retry."
            ))
        }

        return findings
    }
}
