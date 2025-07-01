package com.example.privateline

/**
 * Networking utility responsible for talking to the Flask backend. This class
 * mirrors the Swift implementation so the Android client can participate in the
 * same end-to-end encrypted protocol. Only a few API endpoints are wrapped to
 * keep the skeleton concise.
 *
 * Usage example:
 * ```kotlin
 * val service = APIService("https://example.com")
 * val pem = service.fetchPublicKey("alice")
 * val ciphertext = service.encryptWithRSA(pem!!, "hello")
 * ```
 */

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import android.util.Base64

/**
 * Minimal networking helper mirroring the iOS APIService. Encryption is
 * performed locally using RSA and AES via standard JCA providers.
 */
class APIService(private val baseUrl: String) {
    private val client = OkHttpClient()
    private var socket: WebSocket? = null

    /**
     * Retrieve the PEM encoded public key for ``username`` from the server.
     *
     * @param username User identifier.
     * @return PEM string or null if the request fails.
     */
    fun fetchPublicKey(username: String): String? {
        val req = Request.Builder().url("$baseUrl/api/public_key/$username").build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) return resp.body?.string()
        }
        return null
    }

    /**
     * Establish a WebSocket connection using the provided JWT token.
     * ``listener`` receives all socket events.
     */
    fun connectWebSocket(token: String, listener: WebSocketListener) {
        val req = Request.Builder().url("$baseUrl/socket.io/?token=$token").build()
        socket = client.newWebSocket(req, listener)
    }

    /**
     * Encrypt ``text`` with the given public key using RSA-OAEP and return a
     * base64 encoded ciphertext string.
     */
    fun encryptWithRSA(pem: String, text: String): String {
        val clean = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")
        val decoded = Base64.decode(clean, Base64.DEFAULT)
        val spec = X509EncodedKeySpec(decoded)
        val key: PublicKey = KeyFactory.getInstance("RSA").generatePublic(spec)
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encrypted = cipher.doFinal(text.toByteArray())
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }
}
