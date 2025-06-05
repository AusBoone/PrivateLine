import SwiftUI

struct ChatView: View {
    @StateObject var viewModel: ChatViewModel
    @State private var showPicker = false

    var body: some View {
        VStack {
            Picker("Conversation", selection: Binding(
                get: { viewModel.selectedGroup == nil ? viewModel.recipient : "g\(viewModel.selectedGroup!)" },
                set: { val in
                    if val.hasPrefix("g") {
                        viewModel.selectedGroup = Int(val.dropFirst())
                    } else {
                        viewModel.selectedGroup = nil
                        viewModel.recipient = val
                    }
                    Task { await viewModel.load() }
                })) {
                ForEach(["alice","bob","carol"], id: \ .self) { u in
                    Text(u).tag(u)
                }
                ForEach(viewModel.groups) { g in
                    Text(g.name).tag("g\(g.id)")
                }
            }
            .pickerStyle(MenuPickerStyle())
            List(viewModel.messages) { msg in
                HStack {
                    Text(msg.content)
                    if let read = msg.read, msg.id != 0 {
                        Spacer()
                        Image(systemName: read ? "checkmark.circle.fill" : "checkmark.circle")
                            .foregroundColor(.gray)
                    }
                    if let fid = msg.file_id {
                        Link("attachment", destination: URL(string: "\(viewModel.api.baseURLString)/files/\(fid)")!)
                    }
                }
                    .accessibilityLabel("Message: \(msg.content)")
            }
            HStack {
                TextField("Message", text: $viewModel.input)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button("Attach") {
                    showPicker = true
                }
                .fileImporter(isPresented: $showPicker, allowedContentTypes: [.data]) { result in
                    if case let .success(url) = result, let data = try? Data(contentsOf: url) {
                        viewModel.attachment = data
                    }
                }
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
