/*
 * ConversationListView.swift
 * Presents all available direct and group conversations so the user can
 * choose which thread to view in ``ChatView``.
 *
 * Usage:
 * ``ConversationListView(viewModel: ChatViewModel(api: ...))``
 *
 * The list refreshes contacts and group metadata on appearance to reflect the
 * server's current state. Selecting an item updates the bound
 * ``ChatViewModel`` via ``selectConversation`` which triggers message loading
 * for the chosen thread.
 */
import SwiftUI

/// Lists known conversations grouped by type. Tapping a row updates the
/// ``ChatViewModel`` and dismisses the view to reveal the refreshed chat.
struct ConversationListView: View {
    /// Shared view model providing conversation metadata and network calls.
    @ObservedObject var viewModel: ChatViewModel
    /// Environment dismiss action used to pop this view off the navigation stack.
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section("Direct Messages") {
                // Show each available contact returned from the backend.
                ForEach(viewModel.contacts, id: \.self) { contact in
                    Button(action: {
                        Task {
                            // Selecting a contact clears any group selection and
                            // loads the appropriate conversation from the server.
                            await viewModel.selectConversation(recipient: contact)
                            dismiss()
                        }
                    }) {
                        Text(contact)
                    }
                }
            }
            Section("Groups") {
                // Present all group chats the user participates in.
                ForEach(viewModel.groups) { group in
                    Button(action: {
                        Task {
                            // Switching to a group chat triggers a message reload
                            // for that group and returns to the main chat view.
                            await viewModel.selectConversation(groupID: group.id)
                            dismiss()
                        }
                    }) {
                        Text(group.name)
                    }
                }
            }
        }
        // Always load the latest conversation metadata when appearing.
        .task {
            await viewModel.fetchContacts()
            await viewModel.fetchGroups()
        }
        .navigationTitle("Conversations")
    }
}
