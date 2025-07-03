/*
 * GroupKeyStoreTests.kt - Validate persistence of group chat AES keys.
 * Stores a key, clears the in-memory cache, and ensures CryptoManager can
 * still encrypt and decrypt messages by loading the key from SharedPreferences.
 */
package com.example.privateline

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Ensures that group keys saved to ``GroupKeyStore`` are recovered
 * automatically by ``CryptoManager`` when required.
 */
class GroupKeyStoreTests {
    @Test
    fun keyPersistsAcrossInstances() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val raw = ByteArray(16) { 0x42.toByte() }
        val key = SecretKeySpec(raw, "AES")

        // Persist key and simulate app restart by clearing CryptoManager cache
        GroupKeyStore.save(ctx, 1, key)
        val field = CryptoManager::class.java.getDeclaredField("groupKeys")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val map = field.get(null) as MutableMap<Int, *>
        map.clear()

        val message = "hi"
        val encrypted = CryptoManager.encryptGroupMessage(message, 1, ctx)
        val decrypted = CryptoManager.decryptGroupMessage(encrypted, 1, ctx)
        assertEquals(message, decrypted)
    }

    @Test
    fun removalDeletesPersistedKey() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val raw = ByteArray(16) { 0x24.toByte() }
        val key = SecretKeySpec(raw, "AES")

        CryptoManager.storeGroupKey(Base64.encodeToString(key.encoded, Base64.NO_WRAP), 2, ctx)
        CryptoManager.removeGroupKey(2, ctx)

        // Attempting to use the key should now fail since it was deleted
        var threw = false
        try {
            CryptoManager.encryptGroupMessage("hi", 2, ctx)
        } catch (_: IllegalStateException) {
            threw = true
        }
        assertEquals(true, threw)
    }

    @Test
    fun listingReturnsPersistedIds() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val first = SecretKeySpec(ByteArray(16) { 0x11.toByte() }, "AES")
        val second = SecretKeySpec(ByteArray(16) { 0x22.toByte() }, "AES")

        GroupKeyStore.save(ctx, 10, first)
        GroupKeyStore.save(ctx, 20, second)

        // ``listGroupIds`` should reveal both stored ids
        val ids = GroupKeyStore.listGroupIds(ctx)
        assertEquals(setOf(10, 20), ids)

        GroupKeyStore.clearAll(ctx)
    }

    @Test
    fun clearingRemovesAllKeys() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val someKey = SecretKeySpec(ByteArray(16) { 0x13.toByte() }, "AES")
        GroupKeyStore.save(ctx, 30, someKey)

        // ``clearAllGroupKeys`` should wipe memory and disk copies
        CryptoManager.storeGroupKey(
            Base64.encodeToString(someKey.encoded, Base64.NO_WRAP),
            30,
            ctx
        )
        CryptoManager.clearAllGroupKeys(ctx)

        var missing = false
        try {
            CryptoManager.encryptGroupMessage("hi", 30, ctx)
        } catch (_: IllegalStateException) {
            missing = true
        }
        assertEquals(true, missing)
    }

    @Test
    fun loadAllReturnsEveryKey() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        GroupKeyStore.save(ctx, 100, SecretKeySpec(ByteArray(16) { 0x44.toByte() }, "AES"))
        GroupKeyStore.save(ctx, 200, SecretKeySpec(ByteArray(16) { 0x55.toByte() }, "AES"))

        val all = GroupKeyStore.loadAll(ctx)
        assertEquals(setOf(100, 200), all.keys)
    }

    @Test
    fun preloadCachesPersistedKeys() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val key = SecretKeySpec(ByteArray(16) { 0x66.toByte() }, "AES")
        GroupKeyStore.save(ctx, 300, key)

        // Clear CryptoManager cache and load from disk
        CryptoManager.clearAllGroupKeys(ctx)
        CryptoManager.preloadPersistedGroupKeys(ctx)

        val msg = "hi"
        val enc = CryptoManager.encryptGroupMessage(msg, 300, ctx)
        val dec = CryptoManager.decryptGroupMessage(enc, 300, ctx)
        assertEquals(msg, dec)
    }

    @Test
    fun rotateReplacesOldKey() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val firstB64 = CryptoManager.rotateGroupKey(400, ctx)
        val secondB64 = CryptoManager.rotateGroupKey(400, ctx)
        assert(firstB64 != secondB64)

        val msg = "hello"
        val encrypted = CryptoManager.encryptGroupMessage(msg, 400, ctx)
        val decrypted = CryptoManager.decryptGroupMessage(encrypted, 400, ctx)
        assertEquals(msg, decrypted)
    }

    @Test
    fun containsReportsPresence() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val key = SecretKeySpec(ByteArray(16) { 0x21.toByte() }, "AES")
        GroupKeyStore.save(ctx, 500, key)

        // ``contains`` should be true for id 500 and false for others
        assertEquals(true, GroupKeyStore.contains(ctx, 500))
        assertEquals(false, GroupKeyStore.contains(ctx, 501))
    }

    @Test
    fun hasGroupKeyChecksMemoryAndDisk() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val key = SecretKeySpec(ByteArray(16) { 0x77.toByte() }, "AES")
        GroupKeyStore.save(ctx, 600, key)

        // Cache is empty initially so ``hasGroupKey`` should still succeed via disk
        assertEquals(true, CryptoManager.hasGroupKey(600, ctx))

        // After loading the key into memory the check should remain true
        CryptoManager.encryptGroupMessage("hi", 600, ctx)
        assertEquals(true, CryptoManager.hasGroupKey(600, null))
    }

    @Test
    fun exportAllReturnsBase64Strings() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val raw = ByteArray(16) { 0x88.toByte() }
        val key = SecretKeySpec(raw, "AES")
        GroupKeyStore.save(ctx, 700, key)

        val exported = GroupKeyStore.exportAll(ctx)
        assertEquals(Base64.encodeToString(raw, Base64.NO_WRAP), exported[700])
    }

    @Test
    fun keysAreStoredEncrypted() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)
        val raw = ByteArray(16) { 0x99.toByte() }
        val key = SecretKeySpec(raw, "AES")
        GroupKeyStore.save(ctx, 800, key)

        // Verify that the plaintext key does not appear in the preference file
        val file = java.io.File(ctx.filesDir.parentFile, "shared_prefs/group_keys.xml")
        val contents = file.readText()
        val b64 = Base64.encodeToString(raw, Base64.NO_WRAP)
        assertEquals(false, contents.contains(b64))
    }

    @Test
    fun invalidKeyLengthRejected() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        GroupKeyStore.clearAll(ctx)

        // Base64 for 128-bit key should trigger validation error
        val shortKey = Base64.encodeToString(ByteArray(16) { 0x12.toByte() }, Base64.NO_WRAP)
        var threw = false
        try {
            CryptoManager.storeGroupKey(shortKey, 900, ctx)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertEquals(true, threw)
    }
}
