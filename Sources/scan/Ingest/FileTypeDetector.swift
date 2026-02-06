import Foundation

/// Detects file type using extension mapping and magic byte inspection
struct FileTypeDetector: Sendable {

    /// Detect file type for a given URL
    func detect(url: URL) -> FileType {
        // Check if it's an app bundle (directory with Contents/MacOS)
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
            let macosDir = url.appendingPathComponent("Contents/MacOS")
            if FileManager.default.fileExists(atPath: macosDir.path) {
                return .app
            }
            return .unknown
        }

        // Try magic bytes first (more reliable than extension)
        if let magicType = detectByMagicBytes(url: url) {
            return magicType
        }

        // Fall back to extension
        return detectByExtension(url: url)
    }

    /// Detect file type from magic bytes (first 8 bytes)
    private func detectByMagicBytes(url: URL) -> FileType? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { handle.closeFile() }

        let headerData = handle.readData(ofLength: 8)
        guard headerData.count >= 4 else { return nil }

        let bytes = [UInt8](headerData)

        // ZIP: PK\x03\x04
        if bytes.count >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B
            && bytes[2] == 0x03 && bytes[3] == 0x04 {
            return .zip
        }

        // xar (PKG): "xar!" (0x78617221)
        if bytes.count >= 4 && bytes[0] == 0x78 && bytes[1] == 0x61
            && bytes[2] == 0x72 && bytes[3] == 0x21 {
            return .pkg
        }

        // Mach-O 64-bit LE (0xCFFAEDFE)
        if bytes.count >= 4 && bytes[0] == 0xCF && bytes[1] == 0xFA
            && bytes[2] == 0xED && bytes[3] == 0xFE {
            return .machO
        }

        // Mach-O 32-bit LE (0xCEFAEDFE)
        if bytes.count >= 4 && bytes[0] == 0xCE && bytes[1] == 0xFA
            && bytes[2] == 0xED && bytes[3] == 0xFE {
            return .machO
        }

        // Mach-O 64-bit BE (0xFEEDFACF)
        if bytes.count >= 4 && bytes[0] == 0xFE && bytes[1] == 0xED
            && bytes[2] == 0xFA && bytes[3] == 0xCF {
            return .machO
        }

        // Mach-O 32-bit BE (0xFEEDFACE)
        if bytes.count >= 4 && bytes[0] == 0xFE && bytes[1] == 0xED
            && bytes[2] == 0xFA && bytes[3] == 0xCE {
            return .machO
        }

        // FAT/Universal Mach-O (0xCAFEBABE)
        // Disambiguate from Java class files: FAT header has arch count in bytes 4-7,
        // which is typically small (< 20), while Java has version numbers (usually >= 44)
        if bytes.count >= 8 && bytes[0] == 0xCA && bytes[1] == 0xFE
            && bytes[2] == 0xBA && bytes[3] == 0xBE {
            let secondWord = UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16
                | UInt32(bytes[6]) << 8 | UInt32(bytes[7])
            if secondWord < 20 {
                return .machO
            }
        }

        // Script: #! (shebang)
        if bytes.count >= 2 && bytes[0] == 0x23 && bytes[1] == 0x21 {
            return .script
        }

        // XML plist: <?xml
        if bytes.count >= 5 && bytes[0] == 0x3C && bytes[1] == 0x3F
            && bytes[2] == 0x78 && bytes[3] == 0x6D && bytes[4] == 0x6C {
            return .plist
        }

        // Binary plist: bplist
        if bytes.count >= 6 && bytes[0] == 0x62 && bytes[1] == 0x70
            && bytes[2] == 0x6C && bytes[3] == 0x69 && bytes[4] == 0x73 && bytes[5] == 0x74 {
            return .plist
        }

        return nil
    }

    /// Detect file type from file extension
    private func detectByExtension(url: URL) -> FileType {
        switch url.pathExtension.lowercased() {
        case "dmg", "sparsebundle", "sparseimage":
            return .dmg
        case "zip", "jar", "ipa":
            return .zip
        case "pkg", "mpkg":
            return .pkg
        case "app":
            return .app
        case "plist":
            return .plist
        case "sh", "bash", "zsh", "py", "rb", "pl", "command":
            return .script
        default:
            return .unknown
        }
    }
}
