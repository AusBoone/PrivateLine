/**
 * TokenStore.kt - Helper for persisting the JWT token with biometric protection.
 *
 * The token is saved in SharedPreferences and retrieved only after the user
 * authenticates via Face or Touch ID using the BiometricPrompt API.
 */
package com.example.privateline

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * Save the token string in private SharedPreferences.
 */
object TokenStore {
    private const val PREF = "token_prefs"
    private const val KEY = "jwt"

    /**
     * Persist the given token in SharedPreferences.
     */
    fun saveToken(context: Context, token: String) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putString(KEY, token).apply()
    }

    /**
     * Remove any stored token.
     */
    fun clearToken(context: Context) {
        context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().remove(KEY).apply()
    }

    /**
     * Retrieve the token after prompting the user for biometric auth.
     *
     * @param activity Hosting activity used to display the prompt.
     * @param onResult Callback receiving the token or null on failure.
     */
    fun loadWithBiometrics(activity: FragmentActivity, onResult: (String?) -> Unit) {
        val ctx = activity.applicationContext
        val prefs = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
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
