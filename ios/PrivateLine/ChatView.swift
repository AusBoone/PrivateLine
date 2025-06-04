import SwiftUI

struct ChatView: View {
    @StateObject var viewModel: ChatViewModel

    var body: some View {
        VStack {
            List(viewModel.messages) { msg in
                Text(msg.content)
            }
            HStack {
                TextField("Message", text: $viewModel.input)
                Button("Send") { Task { await viewModel.send() } }
            }
        }
        .onAppear { Task { await viewModel.load() } }
        .onDisappear { viewModel.disconnect() }
        .padding()
    }
}
