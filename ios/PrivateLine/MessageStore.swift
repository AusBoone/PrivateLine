import Foundation

/// Simple persistence layer for caching messages locally on disk.
/// This is not a full database but provides minimal offline support.
enum MessageStore {
    private static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("messages.json")
    }

    /// Load cached messages from disk.
    static func load() -> [Message] {
        guard let data = try? Data(contentsOf: fileURL),
              let msgs = try? JSONDecoder().decode([Message].self, from: data) else {
            return []
        }
        return msgs
    }

    /// Persist messages to disk asynchronously.
    static func save(_ messages: [Message]) {
        DispatchQueue.global(qos: .background).async {
            if let data = try? JSONEncoder().encode(messages) {
                try? data.write(to: fileURL)
            }
        }
    }
}

