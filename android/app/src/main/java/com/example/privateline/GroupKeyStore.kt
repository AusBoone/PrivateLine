// GroupKeyStore.kt - Persistent storage for group chat AES keys.
//
// Provides helper methods for saving and loading symmetric keys used for
// encrypted group conversations. Keys are encoded as base64 strings and
// stored in ``EncryptedSharedPreferences`` so they survive application
// restarts without being written to disk in plaintext. Helpers exist to
// enumerate stored IDs, check for the presence of a key, export all keys
// for backup, and wipe them when logging out. This file mirrors the
// approach taken by the iOS client so both platforms behave identically. The
// base64 format and 256-bit AES key length ensure compatibility with the
// backend API and React frontend.
package com.example.privateline

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Utility object for persisting group chat encryption keys.
 *
 * Keys are saved in SharedPreferences under entries formatted as
 * "group_<ID>" where <ID> is the group identifier. The values are
 * base64 encoded and decoded when retrieved.
 */
object GroupKeyStore {
    private const val PREFS = "group_keys"

    /** Obtain an encrypted SharedPreferences instance used for storing keys. */
    private fun prefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Save ``key`` for the specified ``groupId``. The key is encoded with
     * base64 so it can be stored as a string.
     */
    fun save(context: Context, groupId: Int, key: SecretKey) {
        val encoded = Base64.encodeToString(key.encoded, Base64.NO_WRAP)
        prefs(context)
            .edit()
            .putString("group_${'$'}groupId", encoded)
            .apply()
    }

    /**
     * Load the AES key for ``groupId`` if present.
     *
     * @return ``SecretKey`` or null when no stored key exists or decoding fails.
     */
    fun load(context: Context, groupId: Int): SecretKey? {
        val b64 = prefs(context)
            .getString("group_${'$'}groupId", null)
            ?: return null
        return try {
            val bytes = Base64.decode(b64, Base64.DEFAULT)
            SecretKeySpec(bytes, "AES")
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Remove any persisted key for ``groupId``. This is used when a user leaves
     * a group chat or rotates keys and wants to clear old material from disk.
     */
    fun delete(context: Context, groupId: Int) {
        prefs(context)
            .edit()
            .remove("group_${'$'}groupId")
            .apply()
    }

    /**
     * Return the set of group ids with persisted keys.
     *
     * This is useful for preloading keys on startup or displaying a list of
     * active group conversations.
     */
    fun listGroupIds(context: Context): Set<Int> {
        return prefs(context)
            .all
            .keys
            .mapNotNull { key ->
                if (key.startsWith("group_")) {
                    key.removePrefix("group_").toIntOrNull()
                } else {
                    null
                }
            }
            .toSet()
    }

    /**
     * Remove every persisted group key from storage.
     *
     * This is typically called when the user logs out to ensure no leftover
     * secrets remain on disk.
     */
    fun clearAll(context: Context) {
        val editor = prefs(context).edit()
        for (id in listGroupIds(context)) {
            editor.remove("group_${'$'}id")
        }
        editor.apply()
    }

    /**
     * Load every persisted group key at once.
     *
     * This is primarily used during application startup so that the
     * ``CryptoManager`` cache can be primed before any messages arrive.
     * Invalid entries are skipped silently to avoid crashing on corrupt
     * preferences.
     *
     * @return Map of group id to ``SecretKey`` containing all valid keys.
     */
    fun loadAll(context: Context): Map<Int, SecretKey> {
        val prefs = prefs(context)
        val result = mutableMapOf<Int, SecretKey>()
        for ((name, value) in prefs.all) {
            if (!name.startsWith("group_")) continue
            val id = name.removePrefix("group_").toIntOrNull() ?: continue
            if (value !is String) continue
            try {
                val bytes = Base64.decode(value, Base64.DEFAULT)
                result[id] = SecretKeySpec(bytes, "AES")
            } catch (_: Exception) {
                // Skip malformed keys
            }
        }
        return result
    }

    /**
     * Determine whether a key has been persisted for ``groupId``.
     *
     * @return ``true`` when a stored value exists, ``false`` otherwise.
     */
    fun contains(context: Context, groupId: Int): Boolean {
        val prefs = prefs(context)
        return prefs.contains("group_${'$'}groupId")
    }

    /**
     * Export all persisted group keys as base64 strings.
     *
     * This is useful for backups or device migration where the raw symmetric
     * keys must be transferred securely to another client.
     *
     * @return Map of group id to base64-encoded key values.
     */
    fun exportAll(context: Context): Map<Int, String> {
        val prefs = prefs(context)
        val result = mutableMapOf<Int, String>()
        for ((name, value) in prefs.all) {
            if (!name.startsWith("group_")) continue
            val id = name.removePrefix("group_").toIntOrNull() ?: continue
            if (value is String) {
                result[id] = value
            }
        }
        return result
    }
}
