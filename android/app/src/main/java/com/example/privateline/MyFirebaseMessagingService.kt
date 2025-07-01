/**
 * MyFirebaseMessagingService.kt - Handles FCM token registration.
 * This service forwards newly issued tokens to the backend API.
 */

package com.example.privateline

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.FirebaseMessaging

/**
 * Service responsible for obtaining the FCM token and registering it with
 * the backend so push notifications can be delivered.
 */
class MyFirebaseMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        APIService(BASE_URL).registerPushToken(token)
    }

    companion object {
        const val BASE_URL = "http://localhost:5000"
        fun ensureTokenRegistered(service: APIService) {
            FirebaseMessaging.getInstance().token.addOnSuccessListener { t ->
                service.registerPushToken(t)
            }
        }
    }
}
