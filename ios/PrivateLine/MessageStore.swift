import Foundation

/// Simple persistence layer for caching messages locally on disk.
/// This is not a full database but provides minimal offline support.
/// Messages are stored in plain JSON because they are already encrypted by
/// ``CryptoManager`` before being sent to the server.
enum MessageStore {
    /// Location of the JSON file used for caching messages.
    private static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("messages.json")
    }

    /// Load cached messages from disk.
    static func load() -> [Message] {
        // Attempt to read the cached JSON file
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
                // Write JSON to disk in the background
                try? data.write(to: fileURL)
            }
        }
    }
}

