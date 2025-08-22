import Foundation

/*
 * MessageStore.swift
 * -------------------
 * Lightweight persistence layer responsible for caching messages on disk.
 *
 * ### Overview
 * Messages are encoded as JSON then encrypted with ``CryptoManager`` before
 * being written to disk using complete file protection. This ensures
 * serialized data remains unreadable without the AES key and that the system
 * does not expose the file while the device is locked.
 *
 * ### Usage
 * ``MessageStore.save([Message])`` – Persist messages asynchronously.
 * ``MessageStore.load()`` – Decrypt and deserialize messages back into
 * application structures.
 *
 * ### Design Notes
 * A simple file-based cache is used instead of a database because messages
 * are already individually encrypted when exchanged with the server. The
 * store adds an extra encryption layer to protect the aggregate cache.
 */
enum MessageStore {
    /// Location of the JSON file used for caching messages.
    private static var fileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("messages.json")
    }

    /// Default number of days messages remain in the cache before expiring.
    private static let defaultTtlDays = 30

    /// Load cached messages from disk.
    ///
    /// - Returns: Array of decrypted ``Message`` objects. Returns an empty
    ///   array when the file is missing, expired, or decryption fails.
    static func load() -> [Message] {
        // Determine the retention window either from user defaults or the
        // default value. Convert days to seconds for comparison.
        let days = UserDefaults.standard.integer(forKey: "retention_days")
        let ttl = Double(days > 0 ? days : defaultTtlDays) * 86_400

        // Remove the cache if it has exceeded the retention period to avoid
        // serving stale content.
        if let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path),
           let modified = attrs[.modificationDate] as? Date,
           Date().timeIntervalSince(modified) > ttl {
            try? FileManager.default.removeItem(at: fileURL)
            return []
        }

        // Read the raw encrypted blob, decrypt it, and decode JSON. Any
        // failure during these steps results in an empty cache to keep the
        // call site simple and safe.
        guard let data = try? Data(contentsOf: fileURL),
              let decrypted = try? CryptoManager.decryptData(data),
              let messages = try? JSONDecoder().decode([Message].self, from: decrypted) else {
            return []
        }
        return messages
    }

    /// Persist messages to disk asynchronously.
    ///
    /// - Parameter messages: Collection of ``Message`` objects to serialize.
    ///
    /// Errors encountered during encoding, encryption, or writing are ignored
    /// since caching is best-effort and should not block the UI. Failures are
    /// simply dropped, resulting in the cache not being updated.
    static func save(_ messages: [Message]) {
        DispatchQueue.global(qos: .background).async {
            // Encode the messages to JSON then encrypt the payload. If either
            // step fails, there is nothing to persist and we exit early.
            guard let json = try? JSONEncoder().encode(messages),
                  let encrypted = try? CryptoManager.encryptData(json) else {
                return
            }

            // Persist the encrypted blob using complete file protection so the
            // system keeps the file inaccessible while the device is locked.
            try? encrypted.write(to: fileURL, options: .completeFileProtection)
        }
    }
}

