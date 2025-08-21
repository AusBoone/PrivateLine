/*
 * WebSocketTests.kt
 *
 * Verifies basic connectivity of the WebSocket API and exercises the
 * reconnection logic provided by ``ReconnectingWebSocketListener``. The tests
 * use OkHttp's MockWebServer so no real network access is required.
 */
package com.example.privateline

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests covering WebSocket connectivity helpers.
 */
class WebSocketTests {
    /**
     * Basic smoke test ensuring the ``connectWebSocket`` helper can be invoked
     * without throwing an exception. The server does not need to exist for this
     * check; we simply verify the method call succeeds.
     */
    @Test
    fun connectDoesNotThrow() {
        val service = APIService("http://localhost:5000")
        service.connectWebSocket("dummy", object : WebSocketListener() {})
        assertTrue(true)
    }

    /**
     * Confirms that ``connectWebSocketWithRetry`` retries the connection and
     * eventually succeeds once a server becomes available. The test first
     * attempts to connect while the server is offline (triggering the offline
     * callback) and then starts the server to verify a reconnection occurs.
     */
    @Test
    fun reconnectsWhenServerComesOnline() {
        // Spin up a server to reserve an open port then immediately shut it
        // down so the initial connection attempt fails.
        val tmpServer = MockWebServer()
        tmpServer.start()
        val port = tmpServer.port
        tmpServer.shutdown()

        val service = APIService("http://localhost:$port")
        val offlineLatch = CountDownLatch(1)
        val openLatch = CountDownLatch(1)

        // Listener signals once the connection is established after retries.
        val delegate = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                openLatch.countDown()
            }
        }

        val reconnecting = service.connectWebSocketWithRetry(
            token = "dummy",
            listener = delegate,
            offlineCallback = { offlineLatch.countDown() },
            baseDelayMs = 10,
            maxDelayMs = 50
        )

        // Wait for the offline callback proving the first attempt failed.
        assertTrue("offline callback not invoked", offlineLatch.await(2, TimeUnit.SECONDS))

        // Bring a new server online on the same port and prepare a WebSocket
        // upgrade response for the reconnection attempt.
        val server = MockWebServer()
        server.start(port)
        server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {}))

        // The listener should eventually connect to the newly started server.
        assertTrue("websocket did not reconnect", openLatch.await(2, TimeUnit.SECONDS))

        reconnecting.stop()
        server.shutdown()
    }
}

