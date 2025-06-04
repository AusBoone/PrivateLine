import SwiftUI

struct ChatView: View {
    @StateObject var viewModel: ChatViewModel

    var body: some View {
        VStack {
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
