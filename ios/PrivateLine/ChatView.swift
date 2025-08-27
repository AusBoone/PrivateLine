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
 * - Displays a ``ProgressView`` overlay while ``ChatViewModel`` performs
 *   network requests and disables interactive controls to prevent duplicate
 *   actions.
 * - Conversation selection moved to a dedicated ``ConversationListView``
 *   pushed via navigation instead of an in-line ``Picker``. This keeps the
 *   chat interface focused on the current thread while still allowing quick
 *   switching between direct and group chats.
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

    /// Human readable name of the currently open conversation. Direct chats
    /// display the recipient's username while group chats show the group's name.
    private var conversationTitle: String {
        if let gid = viewModel.selectedGroup {
            return viewModel.groups.first(where: { $0.id == gid })?.name ?? "Group \(gid)"
        }
        return viewModel.recipient.isEmpty ? "Select Conversation" : viewModel.recipient
    }

    var body: some View {
        ZStack {
            VStack {
                // Navigation link displaying the active conversation. Selecting
                // it presents ``ConversationListView`` so the user can switch
                // threads. The label reflects the current selection.
                NavigationLink(destination: ConversationListView(viewModel: viewModel)) {
                    HStack {
                        Text(conversationTitle)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Image(systemName: "chevron.right")
                    }
                }
                .disabled(viewModel.isLoading)

                // Show decrypted chat messages with read receipts and attachments.
                List(viewModel.messages) { msg in
                    MessageRow(message: msg, baseURL: viewModel.api.baseURLString)
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
                .disabled(viewModel.isLoading)
            }
            // Load contacts and initial messages, then connect the WebSocket.
            .onAppear { Task { await load() } }
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

            if viewModel.isLoading {
                ProgressView()
            }
        }
    }

    /// Orchestrates initial data loading for the view.
    /// Fetches contacts before requesting message history so that
    /// ``ConversationListView`` presents up-to-date usernames even if message
    /// loading fails.
    /// Errors from either step are captured within ``ChatViewModel`` via
    /// ``lastError`` and surfaced through the bound alert.
    private func load() async {
        // Retrieve available contacts first; this may fail independently of
        // message retrieval (e.g. network hiccup) but we still attempt to load
        // messages so previously cached conversations appear.
        await viewModel.fetchContacts()
        // Load conversation history and establish the WebSocket connection.
        await viewModel.load()
    }
}
