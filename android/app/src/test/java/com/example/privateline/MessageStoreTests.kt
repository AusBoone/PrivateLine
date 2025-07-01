/*
 * MessageStoreTests.kt - Verify persistence of message cache.
 * Saves and reloads a list of strings on disk.
 */
package com.example.privateline

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Ensure messages persist to disk and load correctly.
 */
class MessageStoreTests {
    @Test
    fun saveAndLoadRoundTrip() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val msgs = listOf("a", "b")
        MessageStore.save(ctx, msgs)
        val loaded = MessageStore.load(ctx)
        assertEquals(msgs, loaded)
    }
}
