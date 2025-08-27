/*
 * ChatView.swift - Main conversation UI in SwiftUI.
 * Presents message history and compose bar using ChatViewModel.
 *
 * Modifications:
 * - Introduced error alert infrastructure bound to ``ChatViewModel``'s
 *   ``lastError`` property. Any new error now triggers a SwiftUI ``Alert``
 *   providing user feedback. The alert automatically clears the error so
 *   subsequent failures produce additional notifications instead of being
 *   suppressed by stale state. ``errorAlertBinding`` now handles this directly
 *   without auxiliary state variables, simplifying the view logic.
 * - Displays a ``ProgressView`` overlay while ``ChatViewModel`` performs
 *   network requests and disables interactive controls to prevent duplicate
 *   actions.
 * - Conversation selection moved to a dedicated ``ConversationListView``
 *   pushed via navigation instead of an in-line ``Picker``. This keeps the
 *   chat interface focused on the current thread while still allowing quick
 *   switching between direct and group chats.
 * - Displays a lightweight attachment preview with a removal button above the
 *   compose field so users can verify and discard attachments before sending.
 * - Replaced the single-line ``TextField`` with an expanding ``TextEditor``
 *   managed by ``@FocusState`` so users can compose multi-line messages while
 *   maintaining keyboard focus.
 * - Wrapped the message list in ``ScrollViewReader`` and observed
 *   ``ChatViewModel.scrollTarget`` to automatically scroll to the newest
 *   message whenever history changes or a send completes.
 */
import SwiftUI

/// SwiftUI view displaying conversations and allowing the user to send
/// encrypted messages. It uses ``ChatViewModel`` for all data handling.
struct ChatView: View {
    /// Object that manages message data and network calls.
    @StateObject var viewModel: ChatViewModel
    /// Tracks whether the file picker modal is visible when attaching files.
    @State private var showPicker = false
    /// Focus binding controlling whether the compose field has keyboard focus.
    @FocusState private var inputFocused: Bool
    /// Dynamic height for the multi-line text editor, capped in the view.
    @State private var editorHeight: CGFloat = 40

    /// Binding controlling presentation of the error ``Alert``.
    ///
    /// The binding reads ``viewModel.lastError`` to decide whether the alert
    /// should be shown. Writing ``false`` (which occurs automatically when the
    /// user dismisses the alert) clears ``lastError`` so future failures can
    /// trigger additional alerts. Writing ``true`` has no effect because the
    /// view model is the single source of truth for when an error exists.
    var errorAlertBinding: Binding<Bool> {
        Binding(
            get: { viewModel.lastError != nil },
            set: { isShowing in
                // When the alert is dismissed ``isShowing`` becomes ``false``.
                // Reset ``lastError`` so subsequent network or send failures
                // present new alerts instead of being suppressed by stale
                // state.
                if !isShowing { viewModel.lastError = nil }
            }
        )
    }

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
                // ``ScrollViewReader`` allows us to programmatically jump to the
                // latest message when ``viewModel.scrollTarget`` changes.
                ScrollViewReader { proxy in
                    List(viewModel.messages) { msg in
                        MessageRow(message: msg, baseURL: viewModel.api.baseURLString)
                            .id(msg.id) // Tag each row so scrollTo can locate it
                    }
                    // Whenever the view model publishes a new scroll target,
                    // animate the list to reveal the message at that identifier.
                    .onChange(of: viewModel.scrollTarget) { target in
                        guard let target = target else { return }
                        withAnimation {
                            proxy.scrollTo(target, anchor: .bottom)
                        }
                    }
                }

                // Preview the selected attachment, if any, so the user can confirm
                // the file before sending. The remove button clears it from the
                // view model to avoid accidentally uploading an unintended file.
                if viewModel.attachment != nil {
                    HStack {
                        HStack {
                            Image(systemName: "doc.fill")
                            Text(viewModel.attachmentFilename ?? "Attachment")
                        }
                        .accessibilityLabel("Attachment \(viewModel.attachmentFilename ?? "file")")
                        Spacer()
                        Button("Remove") {
                            viewModel.removeAttachment()
                        }
                        .accessibilityLabel("Remove attachment")
                    }
                    .padding(8)
                    .background(Color.secondary.opacity(0.2))
                    .cornerRadius(8)
                }

                // Input field, optional attachment picker and send button.
                HStack(alignment: .bottom) {
                    // Multi-line editor bound to the view model's input. The
                    // custom ``ExpandingTextEditor`` adjusts its height to fit
                    // the content up to a reasonable maximum and uses
                    // ``@FocusState`` so the keyboard remains active after sending.
                    ExpandingTextEditor(text: $viewModel.input, height: $editorHeight)
                        .frame(minHeight: editorHeight, maxHeight: editorHeight)
                        .focused($inputFocused)
                        .padding(4)
                        .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.secondary))
                    // Optional attachment picker presented modally
                    Button("Attach") {
                        showPicker = true
                    }
                    .fileImporter(isPresented: $showPicker, allowedContentTypes: [.data]) { result in
                        if case let .success(url) = result,
                           let data = try? Data(contentsOf: url) {
                            // Persist both data and filename so the preview above
                            // can present meaningful context. Users can later remove it.
                            viewModel.selectAttachment(data: data, filename: url.lastPathComponent)
                        }
                    }
                    // Choose optional expiration time for the message
                    Stepper(value: $viewModel.expiresInMinutes, in: 0...1440, step: 10) {
                        Text(
                            viewModel.expiresInMinutes == 0
                                ? "No expiry"
                                : "Expires in \(Int(viewModel.expiresInMinutes)) min"
                        )
                        .font(.caption)
                    }
                    // Tapping the send icon encrypts and uploads the message
                    Button(action: {
                        Task {
                            await viewModel.send()
                            // Restore focus so the keyboard stays visible for rapid replies.
                            inputFocused = true
                        }
                    }) {
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
            // ``errorAlertBinding`` drives presentation and clears the error when
            // the alert is dismissed so subsequent failures remain visible.
            .alert("Error", isPresented: errorAlertBinding) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(viewModel.lastError ?? "Unknown error")
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
