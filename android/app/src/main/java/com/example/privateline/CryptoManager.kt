package com.example.privateline

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
 * integrity through authentication tags.
 *
 * Usage example:
 * ```kotlin
 * val encrypted = CryptoManager.encryptData(data)
 * val plain = CryptoManager.decryptData(encrypted)
 * ```
 */
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
     * Store a base64 encoded AES key for the given group id.
     */
    fun storeGroupKey(b64: String, groupId: Int) {
        val bytes = Base64.decode(b64, Base64.DEFAULT)
        groupKeys[groupId] = SecretKeySpec(bytes, "AES")
    }

    /**
     * Encrypt a group message using the stored key for `groupId`.
     */
    fun encryptGroupMessage(message: String, groupId: Int): String {
        val key = groupKeys[groupId] ?: error("Missing group key")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val encrypted = cipher.doFinal(message.toByteArray())
        return Base64.encodeToString(nonce + encrypted, Base64.NO_WRAP)
    }

    /**
     * Decrypt a base64 encoded group message.
     */
    fun decryptGroupMessage(b64: String, groupId: Int): String {
        val key = groupKeys[groupId] ?: error("Missing group key")
        val bytes = Base64.decode(b64, Base64.DEFAULT)
        val nonce = bytes.sliceArray(0 until 12)
        val ct = bytes.sliceArray(12 until bytes.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val plain = cipher.doFinal(ct)
        return String(plain)
    }
}

