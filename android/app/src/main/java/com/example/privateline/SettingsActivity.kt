package com.example.privateline

import android.content.SharedPreferences
import android.os.Bundle
import com.example.privateline.SecureActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.preference.PreferenceManager
import android.widget.Switch

/**
 * SettingsActivity.kt - Simple screen exposing dark mode and push notification
 * preferences. The chosen options are persisted via SharedPreferences so they
 * survive app restarts.
 */
class SettingsActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)

        // Basic layout with two switches created programmatically to avoid
        // additional XML resources in this demo project.
        val darkSwitch = Switch(this).apply {
            text = "Dark Mode"
            isChecked = prefs.getBoolean("dark_mode", false)
            setOnCheckedChangeListener { _, checked ->
                prefs.edit().putBoolean("dark_mode", checked).apply()
                val mode = if (checked) AppCompatDelegate.MODE_NIGHT_YES else AppCompatDelegate.MODE_NIGHT_NO
                AppCompatDelegate.setDefaultNightMode(mode)
            }
        }

        val pushSwitch = Switch(this).apply {
            text = "Push Notifications"
            isChecked = prefs.getBoolean("push_enabled", true)
            setOnCheckedChangeListener { _, checked ->
                prefs.edit().putBoolean("push_enabled", checked).apply()
                if (checked) {
                    MyFirebaseMessagingService.ensureTokenRegistered(APIService(baseUrl = "http://localhost:5000"))
                } else {
                    // No endpoint for deregistration; token simply not sent
                }
            }
        }

        val retentionInput = android.widget.EditText(this).apply {
            hint = "Retention days"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setText(prefs.getInt("retention_days", 30).toString())
            setOnFocusChangeListener { _, hasFocus ->
                if (!hasFocus) {
                    val days = text.toString().toIntOrNull() ?: 30
                    prefs.edit().putInt("retention_days", days).apply()
                    APIService(baseUrl = "http://localhost:5000").updateRetention(days)
                }
            }
        }

        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            addView(darkSwitch)
            addView(pushSwitch)
            addView(retentionInput)
        }

        setContentView(layout)
    }
}
