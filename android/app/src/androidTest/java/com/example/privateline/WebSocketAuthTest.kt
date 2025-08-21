package com.example.privateline

/*
 * WebSocketAuthTest.kt
 * Verifies that APIService attaches JWT credentials via the Authorization
 * header when initiating a WebSocket connection. A MockWebServer simulates the
 * backend and inspects the upgrade request. This instrumentation test requires
 * a device or emulator but does not rely on any external network services.
 */

import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.WebSocketListener
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.TimeUnit

/**
 * Instrumentation tests run on an Android device or emulator.
 * This suite ensures the Authorization header is present during WebSocket
 * authentication, preventing regressions that could break backend security.
 */
@RunWith(AndroidJUnit4::class)
class WebSocketAuthTest {

    /**
     * Ensure connectWebSocket transmits the JWT in an Authorization header. The
     * MockWebServer upgrades the connection and we inspect the handshake
     * request to confirm the header is set.
     */
    @Test
    fun authorizationHeaderPresent() {
        val server = MockWebServer()
        // Respond to the initial upgrade request with a WebSocket handshake.
        server.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {}))
        server.start()

        // Build APIService pointing to the MockWebServer's base URL.
        val service = APIService(server.url("/").toString().trimEnd('/'))

        // Attempt to connect using a known token.
        val token = "test-token"
        service.connectWebSocket(token, object : WebSocketListener() {})

        // The server records the handshake request for inspection.
        val recorded = server.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("Bearer $token", recorded?.getHeader("Authorization"))

        server.shutdown()
    }
}
