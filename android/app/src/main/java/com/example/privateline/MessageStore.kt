package com.example.privateline

import android.content.Context
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File

/**
 * Simple persistence helper for caching encrypted messages on disk.
 * Messages are stored in JSON format because encryption occurs before
 * they reach this layer. The cache is loaded at startup so offline
 * conversations remain accessible.
 */
object MessageStore {
    private const val FILE_NAME = "messages.json"

    /**
     * Load cached messages from the application's files directory.
     *
     * @param context Application context used to resolve the cache location.
     * @return List of messages previously stored or an empty list if none.
     */
    fun load(context: Context): List<String> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) {
            return emptyList()
        }
        return try {
            val text = file.readText()
            val type = object : TypeToken<List<String>>() {}.type
            Gson().fromJson<List<String>>(text, type) ?: emptyList()
        } catch (e: Exception) {
            // Corrupt cache should not crash the app
            emptyList()
        }
    }

    /**
     * Persist messages to disk. Runs synchronously; callers should
     * offload to a background thread if writing large lists.
     *
     * @param context Application context used to resolve the cache location.
     * @param messages List of encrypted message strings.
     */
    fun save(context: Context, messages: List<String>) {
        val file = File(context.filesDir, FILE_NAME)
        try {
            val json = Gson().toJson(messages)
            file.writeText(json)
        } catch (_: Exception) {
            // Ignore disk write errors
        }
    }
}
