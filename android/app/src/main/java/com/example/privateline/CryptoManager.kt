package com.example.privateline

import android.content.Context
import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CryptoManager.kt - Symmetric encryption utilities used by the Android client.
 *
 * This object mirrors the functionality of the Swift `CryptoManager` so that
 * attachments and group messages can be encrypted locally before being sent to
 * the backend. AES/GCM is used since it provides confidentiality as well as
 * integrity through authentication tags. The data formats mirror those used by
 * the iOS client and React frontend so group messages and attachments remain
 * interoperable with the Python backend.
 *
 * This revision rejects group keys that are not exactly 256 bits long to match
 * the backend database schema and iOS implementation.
 *
 * Usage example:
 * ```kotlin
 * val encrypted = CryptoManager.encryptData(data)
 * val plain = CryptoManager.decryptData(encrypted)
 * ```
 */
// Group chat AES keys may be persisted via ``GroupKeyStore`` so encrypted
// conversations continue working after an app restart. Additional helpers like
// ``hasGroupKey`` and ``preloadPersistedGroupKeys`` provide control over
// when keys are loaded from disk. Keys can also be removed from both memory and
// disk using ``removeGroupKey`` or cleared en masse with ``clearAllGroupKeys``
// when the user logs out or resets the app.
object CryptoManager {
    // AES key cached in memory for the lifetime of the process
    private var aesKey: SecretKey? = null

    // In-memory store of per-group AES keys
    private val groupKeys: MutableMap<Int, SecretKey> = mutableMapOf()

    /**
     * Compute a SHA-256 fingerprint for the provided PEM encoded public key.
     * The resulting string is formatted as colon separated hex pairs.
     */
    fun fingerprintFromPem(pem: String): String {
        val clean = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\n", "")
        val decoded = Base64.decode(clean, Base64.DEFAULT)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(decoded)
        return digest.joinToString(":") { String.format("%02X", it) }
    }


    /**
     * Generate or load the symmetric AES key. In a real application this should
     * be stored securely using Android Keystore, but for this demo the key is
     * kept only in memory.
     */
    private fun key(): SecretKey {
        if (aesKey == null) {
            val gen = KeyGenerator.getInstance("AES")
            gen.init(256)
            aesKey = gen.generateKey()
        }
        return aesKey as SecretKey
    }

    /**
     * Encrypt arbitrary binary data with AES-GCM. The output format is
     * nonce || ciphertext where the nonce is 12 bytes long.
     */
    fun encryptData(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key(), spec)
        val encrypted = cipher.doFinal(data)
        return nonce + encrypted
    }

    /**
     * Decrypt data previously produced by `encryptData`.
     */
    fun decryptData(payload: ByteArray): ByteArray {
        val nonce = payload.sliceArray(0 until 12)
        val ct = payload.sliceArray(12 until payload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key(), spec)
        return cipher.doFinal(ct)
    }

    /**
     * Store a base64 encoded AES key for the given group id. If ``context`` is
     * supplied the key is also persisted via ``GroupKeyStore`` so it can be
     * restored on the next application launch.
     */
    fun storeGroupKey(b64: String, groupId: Int, context: Context? = null) {
        val bytes = try {
            Base64.decode(b64, Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid base64 group key", e)
        }
        if (bytes.size != 32) {
            throw IllegalArgumentException("Group key must be 256 bits")
        }
        val key = SecretKeySpec(bytes, "AES")
        groupKeys[groupId] = key
        if (context != null) {
            GroupKeyStore.save(context, groupId, key)
        }
    }

    /**
     * Check whether a key for ``groupId`` is available either in memory or,
     * if ``context`` is provided, in ``GroupKeyStore``.
     */
    fun hasGroupKey(groupId: Int, context: Context? = null): Boolean {
        if (groupKeys.containsKey(groupId)) return true
        return context?.let { GroupKeyStore.contains(it, groupId) } ?: false
    }

    /**
     * Retrieve the AES key for ``groupId``. Keys are loaded from memory first
     * and fall back to ``GroupKeyStore`` when a ``context`` is provided.
     */
    private fun groupKey(groupId: Int, context: Context? = null): SecretKey {
        groupKeys[groupId]?.let { return it }
        if (context != null) {
            val stored = GroupKeyStore.load(context, groupId)
            if (stored != null) {
                groupKeys[groupId] = stored
                return stored
            }
        }
        error("Missing group key")
    }

    /**
     * Encrypt a group message using the stored key for ``groupId``. When the
     * key is not present in memory and a ``context`` is provided, ``GroupKeyStore``
     * will be queried automatically.
     */
    fun encryptGroupMessage(message: String, groupId: Int, context: Context? = null): String {
        val key = groupKey(groupId, context)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val encrypted = cipher.doFinal(message.toByteArray())
        return Base64.encodeToString(nonce + encrypted, Base64.NO_WRAP)
    }

    /**
     * Decrypt a base64 encoded group message previously produced by
     * ``encryptGroupMessage``. As with encryption, the key is loaded from the
     * ``GroupKeyStore`` when not already cached and a ``context`` is supplied.
     */
    fun decryptGroupMessage(b64: String, groupId: Int, context: Context? = null): String {
        val key = groupKey(groupId, context)
        val bytes = Base64.decode(b64, Base64.DEFAULT)
        val nonce = bytes.sliceArray(0 until 12)
        val ct = bytes.sliceArray(12 until bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val plain = cipher.doFinal(ct)
        return String(plain)
    }

    /**
     * Remove the key for ``groupId`` from the in-memory cache and, when
     * ``context`` is provided, from the persistent ``GroupKeyStore`` as well.
     * This is typically called when leaving a group chat so old keys are not
     * retained.
     */
    fun removeGroupKey(groupId: Int, context: Context? = null) {
        groupKeys.remove(groupId)
        if (context != null) {
            GroupKeyStore.delete(context, groupId)
        }
    }

    /**
     * Clear all cached group keys from memory and, if ``context`` is provided,
     * from the persistent ``GroupKeyStore`` as well.
     *
     * This method is called during logout to ensure no group chat secrets
     * linger on disk.
     */
    fun clearAllGroupKeys(context: Context? = null) {
        groupKeys.clear()
        if (context != null) {
            GroupKeyStore.clearAll(context)
        }
    }

    /**
     * Preload all persisted group keys into the in-memory cache.
     *
     * Call this during application startup so group messages can be
     * decrypted without hitting disk for each one. Invalid keys are
     * ignored silently.
     */
    fun preloadPersistedGroupKeys(context: Context) {
        val stored = GroupKeyStore.loadAll(context)
        groupKeys.putAll(stored)
    }

    /**
     * Generate a brand new AES key for ``groupId`` replacing any existing one.
     * The key is cached in memory and persisted when ``context`` is provided.
     *
     * @return Base64 encoded string representation of the new key so it can be
     *         shared with group members via the backend.
     */
    fun rotateGroupKey(groupId: Int, context: Context? = null): String {
        val gen = KeyGenerator.getInstance("AES")
        gen.init(256)
        val newKey = gen.generateKey()
        groupKeys[groupId] = newKey
        if (context != null) {
            GroupKeyStore.save(context, groupId, newKey)
        }
        return Base64.encodeToString(newKey.encoded, Base64.NO_WRAP)
    }
}

