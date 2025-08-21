package com.example.privateline

/*
 * LoginResponsivenessTest.kt
 * Verifies that APIService.login performs network operations asynchronously so
 * the UI thread remains responsive. The test simulates a slow server response
 * and ensures a runnable posted after invoking login still executes promptly on
 * the main thread.
 */

import android.os.Handler
import android.os.Looper
import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Instrumentation tests verifying that the login API is non-blocking and that
 * callbacks are delivered on the main thread, preserving UI responsiveness.
 */
@RunWith(AndroidJUnit4::class)
class LoginResponsivenessTest {

    /**
     * Ensure that invoking login does not block the main thread and that the
     * callback executes on it. A delayed MockWebServer response is used to
     * emulate network latency.
     */
    @Test
    fun mainThreadStaysResponsiveDuringLogin() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("{\"access_token\":\"abc\"}")
                .setBodyDelay(1, TimeUnit.SECONDS)
        )
        server.start()
        val service = APIService(server.url("/").toString().removeSuffix("/"))

        val handler = Handler(Looper.getMainLooper())
        val latch = CountDownLatch(1)
        val responsive = AtomicBoolean(false)
        val callbackOnMain = AtomicBoolean(false)

        handler.post {
            service.login("user", "pass") { _ ->
                // Record that the callback executed on the main thread
                callbackOnMain.set(Looper.myLooper() == Looper.getMainLooper())
                latch.countDown()
            }
            // If the login were blocking, this runnable would not execute until
            // after the network call finishes.
            handler.post { responsive.set(true) }
        }

        // Wait for login completion and verify our responsiveness flag fired.
        assertTrue(latch.await(3, TimeUnit.SECONDS))
        assertTrue("Main thread was blocked during login", responsive.get())
        assertTrue("Callback did not execute on main thread", callbackOnMain.get())

        server.shutdown()
    }
}
