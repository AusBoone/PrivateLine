/*
 * ChatView.swift - Main conversation UI in SwiftUI.
 * Presents message history and compose bar using ChatViewModel.
 *
 * Modifications:
 * - Introduced error alert infrastructure bound to ``ChatViewModel``'s
 *   ``lastError`` property. Any new error now triggers a SwiftUI ``Alert``
 *   providing user feedback. The alert automatically clears the error so
 *   subsequent failures produce additional notifications instead of being
 *   suppressed by stale state.
 */
import SwiftUI

/// SwiftUI view displaying conversations and allowing the user to send
/// encrypted messages. It uses ``ChatViewModel`` for all data handling.

struct ChatView: View {
    /// Object that manages message data and network calls.
    @StateObject var viewModel: ChatViewModel
    /// Tracks whether the file picker modal is visible when attaching files.
    @State private var showPicker = false
    /// Toggles presentation of an error ``Alert`` bound to ``viewModel.lastError``.
    @State private var showError = false

    var body: some View {
        VStack {
            // Picker allowing the user to switch between direct and group chats.
            Picker("Conversation", selection: Binding(
                get: { viewModel.selectedGroup == nil ? viewModel.recipient : "g\(viewModel.selectedGroup!)" },
                set: { val in
                    if val.hasPrefix("g") {
                        viewModel.selectedGroup = Int(val.dropFirst())
                    } else {
                        viewModel.selectedGroup = nil
                        viewModel.recipient = val
                    }
                    // Reload messages for the newly selected conversation
                    Task { await viewModel.load() }
                })) {
                // Hardcoded demo users for direct chats
                ForEach(["alice","bob","carol"], id: \ .self) { u in
                    Text(u).tag(u)
                }
                // Dynamically loaded group conversations
                ForEach(viewModel.groups) { g in
                    Text(g.name).tag("g\(g.id)")
                }
            }
            .pickerStyle(MenuPickerStyle())
            // Show decrypted chat messages with read receipts and attachments.
            List(viewModel.messages) { msg in
                HStack {
                    Text(msg.content)
                    if let read = msg.read, msg.id != 0 {
                        Spacer()
                        Image(systemName: read ? "checkmark.circle.fill" : "checkmark.circle")
                            .foregroundColor(.gray)
                    }
                    if let fid = msg.file_id {
                        // Download link for an optional file attachment
                        Link("attachment", destination: URL(string: "\(viewModel.api.baseURLString)/files/\(fid)")!)
                    }
                }
                    .accessibilityLabel("Message: \(msg.content)")
            }
            // Input field, optional attachment picker and send button.
            HStack {
                // Text field bound to the view model's input
                TextField("Message", text: $viewModel.input)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                // Optional attachment picker presented modally
                Button("Attach") {
                    showPicker = true
                }
                .fileImporter(isPresented: $showPicker, allowedContentTypes: [.data]) { result in
                    if case let .success(url) = result, let data = try? Data(contentsOf: url) {
                        viewModel.attachment = data
                    }
                }
                // Choose optional expiration time for the message
                Stepper(value: $viewModel.expiresInMinutes, in: 0...1440, step: 10) {
                    Text(viewModel.expiresInMinutes == 0 ? "No expiry" : "Expires in \(Int(viewModel.expiresInMinutes)) min")
                        .font(.caption)
                }
                // Tapping the send icon encrypts and uploads the message
                Button(action: { Task { await viewModel.send() } }) {
                    Image(systemName: "paperplane.fill")
                }
                .accessibilityLabel("Send message")
            }
        }
        // Load initial messages and connect the WebSocket when shown
        .onAppear { Task { await viewModel.load() } }
        // Persist state and close the socket when the view disappears
        .onDisappear { viewModel.disconnect() }
        .padding()
        // Animate list updates when new messages arrive
        .animation(.default, value: viewModel.messages)
        // Present human readable errors surfaced by the view model.
        .alert("Error", isPresented: $showError, presenting: viewModel.lastError) { _ in
            // Reset error once dismissed so future failures display again.
            Button("OK", role: .cancel) { viewModel.lastError = nil }
        } message: { err in
            Text(err)
        }
        // Whenever a new error arrives, toggle the alert visibility.
        .onChange(of: viewModel.lastError) { newValue in
            showError = newValue != nil
        }
    }
}
