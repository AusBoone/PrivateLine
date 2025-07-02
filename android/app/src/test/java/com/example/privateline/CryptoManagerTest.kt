package com.example.privateline

import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Unit tests covering basic CryptoManager functionality. The tests run on the
 * JVM without requiring the Android framework.
 */
class CryptoManagerTest {
    @Test
    fun roundTripEncryption() {
        val message = "hello".toByteArray()
        val encrypted = CryptoManager.encryptData(message)
        val decrypted = CryptoManager.decryptData(encrypted)
        // Ensure that decrypted bytes match original input
        assertArrayEquals(message, decrypted)
    }
}
