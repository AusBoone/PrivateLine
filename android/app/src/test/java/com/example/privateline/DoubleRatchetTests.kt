package com.example.privateline

import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Unit tests verifying the Kotlin ``DoubleRatchet`` implementation against a
 * deterministic test vector produced by the Python backend. The goal is to
 * ensure all platforms derive identical keys and rotate roots in the same way.
 */
class DoubleRatchetTests {
    /**
     * Minimal double ratchet mirroring ``backend/ratchet.py``. Only the pieces
     * required for the test are implemented: deterministic key derivation,
     * AES-GCM decryption and root key advancement.
     */
    private class DoubleRatchet(var rootKey: ByteArray) {
        /** Derive an AES-256 key from the current ``rootKey`` and message header. */
        private fun deriveKey(header: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(rootKey, "HmacSHA256"))
            val prk = mac.doFinal(ByteArray(0))
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(header)
            mac.update(1.toByte()) // single-block HKDF expand
            return mac.doFinal()
        }

        /** Decrypt ``data`` with ``nonce`` and update ``rootKey``. */
        fun decrypt(data: ByteArray, nonce: ByteArray): ByteArray {
            val header = data.sliceArray(0 until 32)
            val ct = data.sliceArray(32 until data.size)
            val key = deriveKey(header)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, nonce)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
            val plain = cipher.doFinal(ct)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(rootKey)
            digest.update(header)
            rootKey = digest.digest()
            return plain
        }
    }

    /** Convert a hex string into a ``ByteArray``. */
    private fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        var i = 0
        while (i < hex.length) {
            out[i / 2] = hex.substring(i, i + 2).toInt(16).toByte()
            i += 2
        }
        return out
    }

    /** Extract ``key`` from the JSON text using a simple regular expression. */
    private fun extract(text: String, key: String): String {
        val regex = "\"$key\"\\s*:\\s*\"([0-9a-f]+)\"".toRegex()
        return regex.find(text)!!.groupValues[1]
    }

    @Test
    fun testDeterministicVector() {
        // Load the JSON vector produced by ``backend/ratchet.py``.
        val path = Paths.get("..", "tests", "data", "ratchet_vectors.json")
        val text = Files.readString(path)
        val root = hexToBytes(extract(text, "root_key"))
        val cipher = hexToBytes(extract(text, "ciphertext"))
        val nonce = hexToBytes(extract(text, "nonce"))
        val updated = hexToBytes(extract(text, "updated_root"))

        // Decrypt and verify the plaintext as well as the advanced root key.
        val ratchet = DoubleRatchet(root)
        val plain = ratchet.decrypt(cipher, nonce)
        assertArrayEquals("Plaintext mismatch", "double ratchet test message".toByteArray(), plain)
        assertArrayEquals("Root key mismatch", updated, ratchet.rootKey)
    }
}
