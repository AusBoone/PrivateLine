import SwiftUI

struct ChatView: View {
    @StateObject var viewModel: ChatViewModel

    var body: some View {
        VStack {
            Picker("Group", selection: $viewModel.groupId) {
                Text("Direct").tag(Int?.none)
                ForEach(0..<viewModel.groups.count, id: \..self) { idx in
                    let item = viewModel.groups[idx]
                    if let id = item["id"] as? Int, let name = item["name"] as? String {
                        Text(name).tag(Int?.some(id))
                    }
                }
            }
            List(viewModel.messages) { msg in
                Text(msg.content)
                    .accessibilityLabel("Message: \(msg.content)")
            }
            HStack {
                TextField("Message", text: $viewModel.input)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button(action: { Task { await viewModel.send() } }) {
                    Image(systemName: "paperplane.fill")
                }
                .accessibilityLabel("Send message")
            }
        }
        .onAppear { Task { await viewModel.load() } }
        .onDisappear { viewModel.disconnect() }
        .padding()
        .animation(.default, value: viewModel.messages)
    }
}
