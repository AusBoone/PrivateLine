/*
 * APIServiceTests.kt - Unit tests for APIService network client.
 * Uses MockWebServer to validate HTTP interactions without a real backend.
 */
package com.example.privateline

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Test suite verifying authentication and message sending behaviour.
 */
class APIServiceTests {
    private lateinit var server: MockWebServer
    private lateinit var service: APIService

    @Before
    fun setup() {
        server = MockWebServer()
        server.start()
        service = APIService(server.url("/").toString().removeSuffix("/"))
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun loginSuccessStoresTokenAndSendsAuthorizedMessage() {
        // Provide successful login and message responses
        server.enqueue(
            MockResponse().setResponseCode(200).setBody("{\"access_token\":\"abc\"}")
        )
        server.enqueue(MockResponse().setResponseCode(200))

        val latch = CountDownLatch(1)
        var loggedIn = false
        service.login("user", "pass") { ok ->
            loggedIn = ok
            latch.countDown()
        }
        // Wait for asynchronous login to finish before sending the message.
        assertTrue(latch.await(1, TimeUnit.SECONDS))
        assertTrue(loggedIn)

        // sendMessage should include Authorization header with token from login
        val result = service.sendMessage("cipher", "bob", "sig", null, null)
        assertTrue(result)

        val loginReq = server.takeRequest()
        assertEquals("/api/login", loginReq.path)
        val msgReq = server.takeRequest()
        assertEquals("/api/messages", msgReq.path)
        assertEquals("Bearer abc", msgReq.getHeader("Authorization"))
    }

    @Test
    fun loginFailureReturnsFalse() {
        server.enqueue(MockResponse().setResponseCode(401))
        val latch = CountDownLatch(1)
        var success = true
        service.login("bad", "creds") { ok ->
            success = ok
            latch.countDown()
        }
        assertTrue(latch.await(1, TimeUnit.SECONDS))
        assertFalse(success)
    }

    @Test
    fun sendMessageWithoutTokenDoesNothing() {
        val sent = service.sendMessage("ct", "alice", "sig", null, null)
        assertFalse(sent)
        // No requests should be recorded when token is missing
        assertEquals(0, server.requestCount)
    }

    /**
     * Verify that markMessageRead posts to the correct endpoint and
     * includes the Authorization header derived from login.
     */
    @Test
    fun markReadUsesAuthToken() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody("{\"access_token\":\"abc\"}")
        )
        server.enqueue(MockResponse().setResponseCode(200))

        val latch = CountDownLatch(1)
        var loggedIn = false
        service.login("user", "pass") { ok ->
            loggedIn = ok
            latch.countDown()
        }
        assertTrue(latch.await(1, TimeUnit.SECONDS))
        assertTrue(loggedIn)
        val ok = service.markMessageRead(5)
        assertTrue(ok)

        server.takeRequest() // login
        val readReq = server.takeRequest()
        assertEquals("/api/messages/5/read", readReq.path)
        assertEquals("Bearer abc", readReq.getHeader("Authorization"))
    }
}
