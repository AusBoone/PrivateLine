/**
 * MyFirebaseMessagingService.kt - Handles FCM token registration.
 * This update persists the last known token in ``SharedPreferences`` so the
 * backend is contacted only when Firebase issues a new identifier. This
 * mirrors the iOS behaviour and prevents redundant network traffic when the
 * token remains unchanged across app launches.
 */

package com.example.privateline

import android.content.Context
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.FirebaseMessaging

/**
 * Service responsible for obtaining the FCM token and registering it with the
 * backend so push notifications can be delivered. Token changes are detected
 * using a simple ``SharedPreferences`` cache.
 */
class MyFirebaseMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = prefs.getString(KEY, null)
        if (stored != token) {
            APIService(BASE_URL).registerPushToken(token)
            prefs.edit().putString(KEY, token).apply()
        }
    }

    companion object {
        /** Backend base URL used by the sample application. */
        const val BASE_URL = "http://localhost:5000"
        private const val PREFS = "push_prefs"
        private const val KEY = "fcm_token"

        /**
         * Ensure the backend knows the current token. Called at app startup to
         * handle the case where ``onNewToken`` was not triggered during this
         * execution.
         */
        fun ensureTokenRegistered(ctx: Context, service: APIService) {
            FirebaseMessaging.getInstance().token.addOnSuccessListener { t ->
                val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                val stored = prefs.getString(KEY, null)
                if (stored != t) {
                    service.registerPushToken(t)
                    prefs.edit().putString(KEY, t).apply()
                }
            }
        }
    }
}
