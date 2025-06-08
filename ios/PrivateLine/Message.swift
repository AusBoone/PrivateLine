import Foundation

/// Basic model representing a chat message returned by the API.
struct Message: Identifiable, Decodable {
    /// Unique identifier for the message.
    let id: Int
    /// Decrypted text content.
    let content: String
    let file_id: Int?
    let read: Bool?
}

struct Group: Identifiable, Decodable {
    /// Unique identifier for the group.
    let id: Int
    /// Human readable group name.
    let name: String
}
