/**
 * ReconnectingWebSocketListener.kt
 *
 * Provides a WebSocketListener implementation that automatically reconnects
 * to the server when the connection is closed or fails. Reconnection attempts
 * use exponential backoff and a callback informs the UI when the socket is
 * offline. This class is kept platform agnostic so it can operate in unit
 * tests without Android dependencies.
 *
 * Usage example:
 * ```kotlin
 * val listener = ReconnectingWebSocketListener(
 *     requestFactory = { buildRequest() },
 *     client = okHttpClient,
 *     delegate = uiListener,
 *     offlineCallback = { showOfflineBanner() }
 * )
 * listener.start()
 * ```
 */
package com.example.privateline

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import kotlin.math.pow

/**
 * Listener that reconnects with exponential backoff when a WebSocket drops.
 *
 * @param requestFactory Lambda producing a fresh Request for each connection
 * attempt. A factory is used so authentication headers can be regenerated if
 * needed.
 * @param client OkHttp client used to create new WebSocket instances.
 * @param delegate Component receiving the standard WebSocket callbacks such as
 * ``onMessage``.
 * @param offlineCallback Invoked whenever ``onFailure`` fires to signal the UI
 * that the socket is offline. Callers typically display an offline banner or
 * indicator when invoked.
 * @param baseDelayMs Initial delay before the first reconnect attempt.
 * @param maxDelayMs Upper bound for the reconnection delay so waits do not grow
 * unbounded.
 * @param scheduler Executor used to schedule delayed reconnect tasks. Defaults
 * to a single threaded executor to keep ordering deterministic.
 */
class ReconnectingWebSocketListener(
    private val requestFactory: () -> Request,
    private val client: OkHttpClient,
    private val delegate: WebSocketListener,
    private val offlineCallback: () -> Unit,
    private val baseDelayMs: Long = 1000,
    private val maxDelayMs: Long = 16000,
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
) : WebSocketListener() {

    /** Tracks how many consecutive reconnection attempts have occurred. */
    private var attemptCount: Int = 0

    /** Latest active WebSocket instance. Useful for sending messages in tests. */
    var currentWebSocket: WebSocket? = null
        private set

    /**
     * Start the initial connection attempt. Must be called once by consumers.
     * Subsequent reconnects happen automatically when the socket closes or
     * fails.
     */
    fun start() {
        connect()
    }

    /**
     * Cease reconnection attempts and close any active socket. Intended for
     * use when the surrounding component is destroyed to avoid leaking threads.
     */
    fun stop() {
        scheduler.shutdownNow()
        currentWebSocket?.close(1000, "client shutdown")
    }

    /** Helper responsible for creating a new WebSocket using the factory. */
    private fun connect() {
        val request = requestFactory()
        currentWebSocket = client.newWebSocket(request, this)
    }

    override fun onOpen(webSocket: WebSocket, response: Response) {
        // Successful connection: reset the backoff counter and forward event.
        attemptCount = 0
        delegate.onOpen(webSocket, response)
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        delegate.onMessage(webSocket, text)
    }

    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        delegate.onMessage(webSocket, bytes)
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        // Forward closure and immediately schedule a reconnect.
        delegate.onClosed(webSocket, code, reason)
        scheduleReconnect()
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        // Notify the UI that the socket is offline before attempting to
        // reconnect. Delegates often log the failure or surface it to users.
        delegate.onFailure(webSocket, t, response)
        offlineCallback()
        scheduleReconnect()
    }

    /**
     * Compute the delay for the next reconnect attempt and schedule it on the
     * executor. The delay grows exponentially up to ``maxDelayMs``.
     */
    private fun scheduleReconnect() {
        val delay = (baseDelayMs * 2.0.pow(attemptCount.toDouble())).toLong()
            .coerceAtMost(maxDelayMs)
        attemptCount++
        scheduler.schedule({ connect() }, delay, TimeUnit.MILLISECONDS)
    }
}

