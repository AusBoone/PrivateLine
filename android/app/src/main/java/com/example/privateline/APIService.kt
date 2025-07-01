/**
 * APIService.kt - Lightweight client for PrivateLine REST API.
 * Provides methods to authenticate, send messages and upload files.
 * Encryption is performed locally using RSA and AES.
 */

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
import android.content.Context
import com.example.privateline.TokenStore

/**
 * Minimal networking helper mirroring the iOS APIService. Encryption is
 * performed locally using RSA and AES via standard JCA providers.
 */

/**
 * Minimal networking helper mirroring the iOS APIService. Encryption is
 * performed locally using RSA and AES via standard JCA providers.
 */
class APIService(private val baseUrl: String) {
    private val client = OkHttpClient()
    private var socket: WebSocket? = null
    private var token: String? = null

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

    /**
     * Perform a login request and cache the returned JWT token. When a
     * ``context`` is supplied the token is also persisted using
     * ``TokenStore`` so it can be unlocked later with biometrics.
     */
    fun login(username: String, password: String, context: Context? = null): Boolean {
        val body = "{\"username\":\"$username\",\"password\":\"$password\"}"
        val req = Request.Builder()
            .url("$baseUrl/api/login")
            .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), body))
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return false
                val tokenValue = Regex("access_token":"([^"]+)").find(json)?.groupValues?.get(1)
                token = tokenValue
                if (context != null && tokenValue != null) {
                    TokenStore.saveToken(context, tokenValue)
                }
                return tokenValue != null
            }
        }
        return false
    }

    /** Register a new account. */
    fun register(username: String, email: String, password: String): Boolean {
        val body = "username=$username&email=$email&password=$password"
        val req = Request.Builder()
            .url("$baseUrl/api/register")
            .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/x-www-form-urlencoded"), body))
            .build()
        client.newCall(req).execute().use { resp ->
            return resp.isSuccessful
        }
    }

    /** Upload encrypted attachment data and return the file id. */
    fun uploadAttachment(data: ByteArray, filename: String): Int? {
        val tok = token ?: return null
        val boundary = "----pl${'$'}{System.currentTimeMillis()}"
        val body = okhttp3.MultipartBody.Builder(boundary)
            .setType(okhttp3.MultipartBody.FORM)
            .addFormDataPart("file", filename, okhttp3.RequestBody.create(null, data))
            .build()
        val req = Request.Builder()
            .url("$baseUrl/api/files")
            .addHeader("Authorization", "Bearer $tok")
            .post(body)
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return null
                return Regex("file_id":(\d+)").find(json)?.groupValues?.get(1)?.toInt()
            }
        }
        return null
    }

    /** Send an encrypted message. */
    fun sendMessage(ciphertext: String, recipient: String, signature: String, fileId: Int?, expiresAt: String?): Boolean {
        val tok = token ?: return false
        val form = okhttp3.FormBody.Builder()
            .add("content", ciphertext)
            .add("recipient", recipient)
            .add("signature", signature)
        if (fileId != null) form.add("file_id", fileId.toString())
        if (expiresAt != null) form.add("expires_at", expiresAt)
        val req = Request.Builder()
            .url("$baseUrl/api/messages")
            .addHeader("Authorization", "Bearer $tok")
            .post(form.build())
            .build()
        client.newCall(req).execute().use { resp ->
            return resp.isSuccessful
        }
    }

    /** Register an FCM token for push notifications. */
    fun registerPushToken(token: String) {
        val tok = this.token ?: return
        val body = "{\"token\":\"$token\",\"platform\":\"android\"}"
        val req = Request.Builder()
            .url("$baseUrl/api/push-token")
            .addHeader("Authorization", "Bearer $tok")
            .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), body))
            .build()
        client.newCall(req).execute().close()
    }

    /**
     * Notify the backend that the specified message has been read.
     *
     * @param id Identifier of the message to mark as read.
     * @return true if the request was successful.
     */
    fun markMessageRead(id: Int): Boolean {
        val tok = token ?: return false
        val req = Request.Builder()
            .url("$baseUrl/api/messages/$id/read")
            .addHeader("Authorization", "Bearer $tok")
            .post(okhttp3.RequestBody.create(null, ByteArray(0)))
            .build()
        client.newCall(req).execute().use { resp ->
            return resp.isSuccessful
        }
    }
}
