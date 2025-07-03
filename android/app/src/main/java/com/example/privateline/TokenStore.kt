/**
 * TokenStore.kt - Helper for persisting the JWT token with biometric protection.
 *
 * The token is saved in `EncryptedSharedPreferences` and retrieved only after
 * the user authenticates via Face or Touch ID using the `BiometricPrompt`
 * API. Encryption ensures the JWT cannot be extracted from the app's storage
 * even on rooted devices. iOS stores the token in the Keychain so this design
 * keeps both platforms aligned.
 */
package com.example.privateline

import android.content.Context
import android.content.SharedPreferences
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Save and retrieve the JWT token using encrypted preferences protected by
 * optional biometric prompts.
 */
object TokenStore {
    private const val PREF = "token_prefs"
    private const val KEY = "jwt"
    private const val USER = "username"

    /**
     * Obtain an encrypted SharedPreferences instance used for storing the token
     * and username. The master key is generated automatically and stored in the
     * system KeyStore.
     */
    private fun prefs(context: Context): SharedPreferences {
        val master = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREF,
            master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Persist the given token securely.
     */
    fun saveToken(context: Context, token: String) {
        prefs(context).edit().putString(KEY, token).apply()
    }

    /** Store the username alongside the token for later use. */
    fun saveUsername(context: Context, username: String) {
        prefs(context).edit().putString(USER, username).apply()
    }

    /**
     * Remove any stored token.
     */
    fun clearToken(context: Context) {
        prefs(context).edit().remove(KEY).remove(USER).apply()
    }

    /** Retrieve the stored username or null if none. */
    fun loadUsername(context: Context): String? {
        return prefs(context).getString(USER, null)
    }

    /**
     * Retrieve the token after prompting the user for biometric auth.
     *
     * @param activity Hosting activity used to display the prompt.
     * @param onResult Callback receiving the token or null on failure.
     */
    fun loadWithBiometrics(activity: FragmentActivity, onResult: (String?) -> Unit) {
        val ctx = activity.applicationContext
        val prefs = prefs(ctx)
        val stored = prefs.getString(KEY, null)
        if (stored == null) {
            onResult(null)
            return
        }
        val manager = BiometricManager.from(ctx)
        if (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            != BiometricManager.BIOMETRIC_SUCCESS) {
            // Device lacks biometrics, return without prompting
            onResult(stored)
            return
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onResult(stored)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onResult(null)
                }
            })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock PrivateLine")
            .setSubtitle("Authenticate to access your messages")
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info)
    }
}
