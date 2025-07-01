/*
 * EncryptionTests.kt - Validate RSA encryption helper.
 * Ensures ciphertext is produced for a sample key.
 */
package com.example.privateline

import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * Verify that RSA encryption produces a base64 string.
 */
class EncryptionTests {
    @Test
    fun rsaEncryptProducesCiphertext() {
        val service = APIService("http://localhost:5000")
        val pem = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALyX...\n-----END PUBLIC KEY-----"
        val ct = service.encryptWithRSA(pem, "hi")
        assertNotNull(ct)
    }
}
