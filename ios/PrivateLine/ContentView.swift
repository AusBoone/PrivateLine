import SwiftUI

/// Root view that displays either the login screen or chat depending on auth state.
struct ContentView: View {
    @StateObject private var api = APIService()

    var body: some View {
        NavigationView {
            if api.isAuthenticated {
                ChatView(viewModel: ChatViewModel(api: api))
                    .navigationTitle("PrivateLine")
            } else {
                LoginView(viewModel: LoginViewModel(api: api))
                    .navigationTitle("PrivateLine")
            }
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
