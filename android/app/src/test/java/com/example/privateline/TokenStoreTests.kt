package com.example.privateline

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Test suite covering encrypted token storage.
 * Ensures tokens are not persisted in plaintext and that
 * clearing preferences removes all saved values.
 */
class TokenStoreTests {
    @Test
    fun tokenStoredEncrypted() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        TokenStore.saveToken(ctx, "secret")
        val file = java.io.File(ctx.filesDir.parentFile, "shared_prefs/token_prefs.xml")
        val text = file.readText()
        assertFalse(text.contains("secret"))
        TokenStore.clearToken(ctx)
    }

    @Test
    fun usernamePersistsAndClears() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        TokenStore.saveUsername(ctx, "alice")
        assertEquals("alice", TokenStore.loadUsername(ctx))
        TokenStore.clearToken(ctx)
        assertEquals(null, TokenStore.loadUsername(ctx))
    }
}
