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

        // Query VirusTotal if API key available
        if let config = try? ScanConfig.load(),
           let apiKey = config.virusTotalAPIKey,
           !apiKey.isEmpty {
            if let vtFinding = await queryVirusTotal(sha256: sha256, apiKey: apiKey, logger: context.logger) {
                findings.append(vtFinding)
            }
        }

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

    // MARK: - VirusTotal API

    /// Query VirusTotal for hash reputation
    private func queryVirusTotal(sha256: String, apiKey: String, logger: VerboseLogger) async -> Finding? {
        let urlString = "https://www.virustotal.com/api/v3/files/\(sha256)"
        guard let url = URL(string: urlString) else { return nil }

        var request = URLRequest(url: url)
        request.setValue("x-apikey \(apiKey)", forHTTPHeaderField: "Authorization")
        request.httpMethod = "GET"
        request.timeoutInterval = 15

        logger.info("Querying VirusTotal for SHA-256: \(sha256)")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else { return nil }

            // Handle rate limiting
            if httpResponse.statusCode == 429 {
                return Finding(
                    id: "reputation_vt_rate_limited",
                    category: .reputation,
                    severity: .info,
                    confidence: .low,
                    summary: "VirusTotal rate limit exceeded",
                    evidence: "HTTP 429",
                    location: nil,
                    remediation: "Wait before retrying or upgrade API tier."
                )
            }

            // Hash not found
            if httpResponse.statusCode == 404 {
                return Finding(
                    id: "reputation_vt_clean",
                    category: .reputation,
                    severity: .info,
                    confidence: .medium,
                    summary: "Not found in VirusTotal",
                    evidence: "Hash not in VT database",
                    location: nil,
                    remediation: nil
                )
            }

            guard httpResponse.statusCode == 200 else { return nil }

            // Parse JSON response
            let json = try JSONDecoder().decode(VTResponse.self, from: data)
            let malicious = json.data.attributes.last_analysis_stats.malicious
            let total = json.data.attributes.last_analysis_stats.total

            if malicious > 0 {
                return Finding(
                    id: "reputation_virustotal",
                    category: .reputation,
                    severity: .high,
                    confidence: .high,
                    summary: "Detected by \(malicious)/\(total) VirusTotal engines",
                    evidence: "Malicious detections: \(malicious), Total scans: \(total)",
                    location: nil,
                    remediation: "File is flagged as malware by multiple AV engines."
                )
            } else {
                return Finding(
                    id: "reputation_vt_clean",
                    category: .reputation,
                    severity: .info,
                    confidence: .high,
                    summary: "Clean in VirusTotal (0/\(total))",
                    evidence: "No detections",
                    location: nil,
                    remediation: nil
                )
            }
        } catch {
            logger.error("VirusTotal query failed: \(error)")
            return nil
        }
    }
}

// MARK: - VirusTotal Response Models

private struct VTResponse: Codable {
    struct Data: Codable {
        struct Attributes: Codable {
            struct Stats: Codable {
                let malicious: Int
                let total: Int
            }
            let last_analysis_stats: Stats
        }
        let attributes: Attributes
    }
    let data: Data
}
