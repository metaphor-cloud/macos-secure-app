import SwiftUI
import SecureAppKit

/// Settings: who is signed in, this Mac's name and key, AI apps, and sign out.
struct SettingsView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var mcp: MCPController
    @State private var copied: String?

    var body: some View {
        Form {
            Section(Copy.Settings.account) {
                if let who = model.identity {
                    LabeledContent("Name", value: who.name)
                    LabeledContent("Email", value: who.email)
                    Button(Copy.Settings.signOut) { model.signOut() }
                } else {
                    Text("Not signed in").foregroundStyle(.secondary)
                }
            }
            Section(Copy.Settings.device) {
                if let record = model.record, record.enrolled {
                    LabeledContent("Name", value: record.deviceLabel)
                    LabeledContent("Key", value: keyRef(record.keyId))
                } else {
                    Text(Copy.Settings.notEnrolled).foregroundStyle(.secondary)
                }
            }
            aiApps
        }
        .formStyle(.grouped)
        .frame(width: 460)
    }

    @ViewBuilder private var aiApps: some View {
        Section(Copy.AIApps.section) {
            Toggle(Copy.AIApps.toggle, isOn: Binding(get: { mcp.enabled }, set: { mcp.setEnabled($0) }))
            Text(Copy.AIApps.about).foregroundStyle(.secondary).font(.callout)
            if mcp.enabled {
                if let error = mcp.error {
                    Text(error).foregroundStyle(.red).font(.callout)
                }
                LabeledContent(Copy.AIApps.url) {
                    Text(mcp.url).textSelection(.enabled).font(.system(.body, design: .monospaced))
                }
                LabeledContent(Copy.AIApps.secret) {
                    HStack {
                        Text("••••••••").foregroundStyle(.secondary)
                        copyButton("secret", mcp.secret ?? "")
                    }
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text(Copy.AIApps.claudeCode).font(.headline)
                    Text(Copy.AIApps.claudeCodeNote).foregroundStyle(.secondary).font(.callout)
                    Text(mcp.claudeCodeCommand(revealed: false))
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                    copyButton("command", mcp.claudeCodeCommand(revealed: true))
                }
                Button(Copy.AIApps.regenerate) {
                    mcp.regenerate()
                    copied = nil
                }
                Text(Copy.AIApps.regenerateNote).foregroundStyle(.secondary).font(.callout)
            }
        }
    }

    private func copyButton(_ what: String, _ text: String) -> some View {
        Button(copied == what ? Copy.AIApps.copied : Copy.AIApps.copy) {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            copied = what
        }
        .disabled(text.isEmpty)
    }
}
