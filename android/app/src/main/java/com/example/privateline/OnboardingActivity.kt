package com.example.privateline

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager

/**
 * OnboardingActivity.kt - First-run experience showing the user's key
 * fingerprint. The activity only appears once and stores a flag in
 * SharedPreferences so subsequent launches bypass onboarding.
 */
class OnboardingActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        if (prefs.getBoolean("onboarded", false)) {
            finish()
            return
        }

        val api = APIService("http://localhost:5000")
        val username = TokenStore.loadUsername(this)
        val fingerprint = if (username != null) {
            val pem = api.fetchPublicKey(username)
            if (pem != null) CryptoManager.fingerprintFromPem(pem) else "unknown"
        } else {
            "unknown"
        }

        val text = TextView(this).apply {
            text = "Public key fingerprint:\n\n$fingerprint"
            textSize = 16f
            setPadding(32, 32, 32, 32)
        }
        setContentView(text)
        prefs.edit().putBoolean("onboarded", true).apply()
    }
}
