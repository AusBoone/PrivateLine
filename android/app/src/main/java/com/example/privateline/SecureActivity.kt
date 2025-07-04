package com.example.privateline

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import android.view.WindowManager

/**
 * SecureActivity.kt - Base class preventing screenshots or screen recording.
 *
 * Activities displaying sensitive information should extend this class instead
 * of [AppCompatActivity]. The default implementation sets the
 * [WindowManager.LayoutParams.FLAG_SECURE] flag which instructs Android to block
 * screenshots, screen recordings and non-secure overlays. No additional
 * behavior is introduced beyond calling through to [AppCompatActivity].
 */
open class SecureActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        // Call into the superclass first so default initialization happens
        super.onCreate(savedInstanceState)
        // Apply the secure flag to prevent screenshots and recordings
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
    }
}
