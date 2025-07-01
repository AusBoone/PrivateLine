/**
 * Message.kt - Data models for chat objects.
 *
 * Provides simple representations matching the backend JSON structure so
 * the Android client can decode responses and persist message state such
 * as read receipts.
 */
package com.example.privateline

import com.google.gson.annotations.SerializedName
import java.util.Date

/**
 * Model representing a single chat message.
 *
 * @property id Unique identifier for the message.
 * @property content Decrypted text body of the message.
 * @property file_id Optional attachment identifier returned when a file is uploaded.
 * @property read Whether the message has been read by the recipient.
 * @property expires_at Optional timestamp when the message should expire locally.
 */
data class Message(
    val id: Int,
    val content: String,
    @SerializedName("file_id") val file_id: Int?,
    val read: Boolean?,
    @SerializedName("expires_at") val expires_at: Date?
)
