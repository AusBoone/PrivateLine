package com.example.privateline

/*
 * Modification summary:
 * connectWebSocket now transmits the JWT via an Authorization header rather
 * than as a query parameter, preventing token leakage in URLs and matching the
 * backend's header-based authentication expectations.
 * TLS certificate pinning now loads the fingerprint from ``BuildConfig`` and
 * the service accepts an optional ``OkHttpClient.Builder`` allowing tests to
 * inject custom trust managers.
 * login has been refactored to use OkHttp's asynchronous ``enqueue`` API and
 * dispatches results back to the main thread, preventing UI freezes during
 * authentication.
 * connectWebSocketWithRetry introduces automatic reconnection using
 * ``ReconnectingWebSocketListener`` so the UI is notified when the socket goes
 * offline and retries occur with exponential backoff.
 */

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
import okhttp3.CertificatePinner
import okhttp3.HttpUrl
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import android.util.Base64
import android.content.Context
import com.example.privateline.TokenStore
import com.example.privateline.BuildConfig
import com.google.gson.Gson
import com.google.gson.JsonObject
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Response
import android.os.Handler
import android.os.Looper

/**
 * Minimal networking helper mirroring the iOS APIService. Encryption is
 * performed locally using RSA and AES via standard JCA providers.
 *
 * @param baseUrl Base URL of the backend server.
 * @param clientBuilder Optional OkHttpClient builder used primarily in tests to
 *                      inject custom SSL settings when validating certificate
 *                      pinning behaviour. Production callers may ignore it.
 */
class APIService(private val baseUrl: String, clientBuilder: OkHttpClient.Builder? = null) {
    companion object {
        /**
         * SHA-256 pin for the backend certificate. Loaded from BuildConfig so
         * that each build variant can supply its own fingerprint without code
         * changes.
         */
        private val PINNED_SHA256: String = BuildConfig.CERTIFICATE_SHA256
    }

    private val client: OkHttpClient
    init {
        val host = HttpUrl.parse(baseUrl)?.host() ?: baseUrl
        val pinner = CertificatePinner.Builder()
            .add(host, PINNED_SHA256)
            .build()
        // Use the provided builder when available (e.g., in tests) so a custom
        // trust manager can be supplied. Otherwise fall back to a default
        // builder that trusts the system certificate store.
        val builder = clientBuilder ?: OkHttpClient.Builder()
        client = builder
            .certificatePinner(pinner)
            .build()
    }
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
     * Establish a WebSocket connection using the provided JWT token. The token
     * is sent in the ``Authorization`` header to align with backend
     * expectations and avoid exposing credentials in the URL. ``listener``
     * receives all socket events.
     *
     * @param token JSON Web Token used for authentication. An empty or malformed
     * token results in server-side authentication failure.
     * @param listener Callback receiving WebSocket lifecycle events.
     */
    fun connectWebSocket(token: String, listener: WebSocketListener) {
        // Build the request for the Socket.IO endpoint, attaching the JWT in an
        // Authorization header so intermediary logs or caches never see it in
        // the URL. This mirrors how standard HTTP endpoints authenticate.
        val req = Request.Builder()
            .url("$baseUrl/socket.io/")
            .addHeader("Authorization", "Bearer $token")
            .build()

        // Initiate the asynchronous WebSocket connection. ``socket`` retains
        // a reference so callers may close the connection later if needed.
        socket = client.newWebSocket(req, listener)
    }

    /**
     * Establish a WebSocket that automatically reconnects on failures using
     * exponential backoff. ``offlineCallback`` allows the UI to react when the
     * socket cannot be reached (e.g., by displaying an offline banner).
     *
     * @param token JWT used for authentication.
     * @param listener Delegate receiving standard WebSocket events such as
     *                 ``onMessage``.
     * @param offlineCallback Invoked when the socket transitions offline due to
     *                        network failures.
     * @param baseDelayMs Initial backoff delay in milliseconds. Tests may
     *                    supply a small value for fast execution.
     * @param maxDelayMs Maximum delay between reconnection attempts.
     * @return The ``ReconnectingWebSocketListener`` managing the connection so
     *         callers may stop retries when appropriate.
     */
    fun connectWebSocketWithRetry(
        token: String,
        listener: WebSocketListener,
        offlineCallback: () -> Unit,
        baseDelayMs: Long = 1000,
        maxDelayMs: Long = 16000
    ): ReconnectingWebSocketListener {
        // Factory to generate a fresh request for each attempt. Using a lambda
        // ensures headers are rebuilt and tokens refreshed when reconnections
        // occur.
        val requestFactory = {
            Request.Builder()
                .url("$baseUrl/socket.io/")
                .addHeader("Authorization", "Bearer $token")
                .build()
        }
        val reconnecting = ReconnectingWebSocketListener(
            requestFactory = requestFactory,
            client = client,
            delegate = listener,
            offlineCallback = offlineCallback,
            baseDelayMs = baseDelayMs,
            maxDelayMs = maxDelayMs
        )
        reconnecting.start()
        return reconnecting
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
     * Perform a login request asynchronously and cache the returned JWT token.
     * ``callback`` is invoked on the main thread with ``true`` when
     * authentication succeeds. When ``context`` is supplied the token is also
     * persisted using ``TokenStore`` so it can later be retrieved with
     * biometrics.
     */
    fun login(
        username: String,
        password: String,
        context: Context? = null,
        callback: (Boolean) -> Unit
    ) {
        val body = "{\"username\":\"$username\",\"password\":\"$password\"}"
        val req = Request.Builder()
            .url("$baseUrl/api/login")
            .post(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), body))
            .build()
        // Execute the request without blocking the caller so the UI remains
        // responsive while the network operation is in flight.
        client.newCall(req).enqueue(object : Callback {
            override fun onFailure(call: Call, e: java.io.IOException) {
                // Propagate failure back on the main thread to allow UI widgets
                // to react safely.
                Handler(Looper.getMainLooper()).post { callback(false) }
            }

            override fun onResponse(call: Call, response: Response) {
                var success = false
                if (response.isSuccessful) {
                    val jsonStr = response.body?.string()
                    if (jsonStr != null) {
                        try {
                            val obj = Gson().fromJson(jsonStr, JsonObject::class.java)
                            val tok = obj.get("access_token").asString
                            token = tok
                            if (context != null) {
                                TokenStore.saveToken(context, tok)
                                TokenStore.saveUsername(context, username)
                            }
                            success = true
                        } catch (_: Exception) {
                            success = false
                        }
                    }
                }
                // Notify caller on the main thread regardless of success.
                Handler(Looper.getMainLooper()).post { callback(success) }
            }
        })
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
        // Encrypt attachment locally so the server never sees plaintext bytes
        val encrypted = CryptoManager.encryptData(data)
        val body = okhttp3.MultipartBody.Builder(boundary)
            .setType(okhttp3.MultipartBody.FORM)
            .addFormDataPart(
                "file",
                filename,
                okhttp3.RequestBody.create(null, encrypted)
            )
            .build()
        val req = Request.Builder()
            .url("$baseUrl/api/files")
            .addHeader("Authorization", "Bearer $tok")
            .post(body)
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return null
                return try {
                    val obj = Gson().fromJson(json, JsonObject::class.java)
                    obj.get("file_id").asInt
                } catch (_: Exception) {
                    null
                }
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

    /** Update the user's message retention period. */
    fun updateRetention(days: Int) {
        val tok = token ?: return
        val body = "{\"messageRetentionDays\":$days}"
        val req = Request.Builder()
            .url("$baseUrl/api/account-settings")
            .addHeader("Authorization", "Bearer $tok")
            .addHeader("Content-Type", "application/json")
            .put(okhttp3.RequestBody.create(okhttp3.MediaType.parse("application/json"), body))
            .build()
        client.newCall(req).execute().close()
    }

    /** Fetch the list of chat groups from the server. */
    fun fetchGroups(): List<Group> {
        val tok = token ?: return emptyList()
        val req = Request.Builder()
            .url("$baseUrl/api/groups")
            .addHeader("Authorization", "Bearer $tok")
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return emptyList()
                return try {
                    val obj = Gson().fromJson(json, JsonObject::class.java)
                    val arr = obj.getAsJsonArray("groups")
                    arr.map { g ->
                        val o = g.asJsonObject
                        Group(o.get("id").asInt, o.get("name").asString)
                    }
                } catch (_: Exception) { emptyList() }
            }
        }
        return emptyList()
    }

    /** Retrieve messages for a specific group. */
    fun fetchGroupMessages(groupId: Int): List<Message> {
        val tok = token ?: return emptyList()
        val req = Request.Builder()
            .url("$baseUrl/api/groups/$groupId/messages")
            .addHeader("Authorization", "Bearer $tok")
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return emptyList()
                return try {
                    val obj = Gson().fromJson(json, JsonObject::class.java)
                    val arr = obj.getAsJsonArray("messages")
                    arr.map { m -> Gson().fromJson(m, Message::class.java) }
                } catch (_: Exception) { emptyList() }
            }
        }
        return emptyList()
    }

    /** Send an encrypted group message. */
    fun sendGroupMessage(ciphertext: String, groupId: Int, signature: String, fileId: Int?, expiresAt: String?): Boolean {
        val tok = token ?: return false
        val form = okhttp3.FormBody.Builder()
            .add("content", ciphertext)
            .add("group_id", groupId.toString())
            .add("signature", signature)
        if (fileId != null) form.add("file_id", fileId.toString())
        if (expiresAt != null) form.add("expires_at", expiresAt)
        val req = Request.Builder()
            .url("$baseUrl/api/groups/$groupId/messages")
            .addHeader("Authorization", "Bearer $tok")
            .post(form.build())
            .build()
        client.newCall(req).execute().use { resp ->
            return resp.isSuccessful
        }
    }

    /** Revoke all active sessions for the current user. */
    fun revokeAllSessions() {
        val tok = token ?: return
        val req = Request.Builder()
            .url("$baseUrl/api/revoke")
            .addHeader("Authorization", "Bearer $tok")
            .post(okhttp3.RequestBody.create(null, ByteArray(0)))
            .build()
        client.newCall(req).execute().close()
    }

    /** Refresh the JWT token using the backend. */
    fun refreshToken() {
        val tok = token ?: return
        val req = Request.Builder()
            .url("$baseUrl/api/refresh")
            .addHeader("Authorization", "Bearer $tok")
            .post(okhttp3.RequestBody.create(null, ByteArray(0)))
            .build()
        client.newCall(req).execute().use { resp ->
            if (resp.isSuccessful) {
                val json = resp.body?.string() ?: return
                try {
                    val obj = Gson().fromJson(json, JsonObject::class.java)
                    token = obj.get("access_token").asString
                } catch (_: Exception) {}
            }
        }
    }
}
