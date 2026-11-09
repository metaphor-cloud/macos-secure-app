import AppKit
import SecureAppKit
import UniformTypeIdentifiers

/// Hands a fetched file to the system: PDFs shown inline open in Preview,
/// everything else is saved where the person chooses.
@MainActor
enum Downloads {
    static func deliver(body: Data, headers: [String: String], path: String, suggestedName: String?, window: NSWindow?) {
        let disposition = headers["Content-Disposition"] ?? ""
        let type = (headers["Content-Type"] ?? "").lowercased()
        let name = suggestedName ?? fileName(fromDisposition: disposition).flatMap(BridgeValidator.sanitiseFileName) ?? fallbackName(path: path, type: type)
        let attachment = disposition.lowercased().hasPrefix("attachment")

        if !attachment, type.hasPrefix("application/pdf") || type.hasPrefix("image/") {
            openInViewer(body: body, name: name)
        } else {
            save(body: body, name: name, window: window)
        }
    }

    static func openInViewer(body: Data, name: String) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("Secure App", isDirectory: true).appendingPathComponent(UUID().uuidString, isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let file = dir.appendingPathComponent(name)
            try body.write(to: file, options: [.atomic, .completeFileProtection])
            NSWorkspace.shared.open(file)
            Log.web.info("opened a file in its viewer")
        } catch {
            Log.web.error("file could not be opened: \(String(describing: type(of: error)), privacy: .public)")
        }
    }

    static func save(body: Data, name: String, window: NSWindow?) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = name
        panel.canCreateDirectories = true
        let write: (NSApplication.ModalResponse) -> Void = { response in
            guard response == .OK, let url = panel.url else { return }
            do {
                try body.write(to: url, options: .atomic)
                Log.web.info("saved a download")
            } catch {
                Log.web.error("download could not be saved")
                NSAlert(error: error).runModal()
            }
        }
        if let window { panel.beginSheetModal(for: window, completionHandler: write) } else { write(panel.runModal()) }
    }

    /// filename= or filename*=UTF-8'' from a Content-Disposition header.
    static func fileName(fromDisposition header: String) -> String? {
        for part in header.split(separator: ";").map({ $0.trimmingCharacters(in: .whitespaces) }) {
            let lower = part.lowercased()
            if lower.hasPrefix("filename*="), let range = part.range(of: "''") {
                return String(part[range.upperBound...]).removingPercentEncoding
            }
            if lower.hasPrefix("filename=") {
                return String(part.dropFirst("filename=".count)).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            }
        }
        return nil
    }

    static func fallbackName(path: String, type: String) -> String {
        let last = String(path.split(separator: "?").first?.split(separator: "/").last ?? "download")
        let ext = UTType(mimeType: type.components(separatedBy: ";").first ?? "")?.preferredFilenameExtension
        if let ext, !last.hasSuffix(".\(ext)") { return "\(last).\(ext)" }
        return last
    }
}
