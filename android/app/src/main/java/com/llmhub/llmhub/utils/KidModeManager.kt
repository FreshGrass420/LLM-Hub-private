package com.llmhub.llmhub.utils

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest

/**
 * Manages the state and security of "Kid Mode".
 * Stores a hashed PIN and an enabled flag in EncryptedSharedPreferences.
 * The PIN is stored as a salted SHA-256 hash, never in plaintext.
 */
class KidModeManager(context: Context) {

    private val prefs: SharedPreferences

    init {
        // Use EncryptedSharedPreferences to securely store the PIN hash
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        prefs = EncryptedSharedPreferences.create(
            context,
            "kid_mode_prefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val _isKidModeEnabled = MutableStateFlow(prefs.getBoolean(KEY_IS_ENABLED, false))
    val isKidModeEnabled: StateFlow<Boolean> = _isKidModeEnabled.asStateFlow()

    fun enableKidMode(pin: String) {
        if (pin.length != 4 || !pin.all { it.isDigit() }) {
            throw IllegalArgumentException("PIN must be 4 digits")
        }
        prefs.edit().apply {
            putBoolean(KEY_IS_ENABLED, true)
            putString(KEY_PIN, hashPin(pin))
            apply()
        }
        _isKidModeEnabled.value = true
        Log.d("KidModeManager", "Kid Mode Enabled")
    }

    fun disableKidMode(pin: String): Boolean {
        if (!verifyPin(pin)) return false
        prefs.edit().apply {
            putBoolean(KEY_IS_ENABLED, false)
            remove(KEY_PIN) // Clear the PIN so it must be reset next time
            apply()
        }
        _isKidModeEnabled.value = false
        Log.d("KidModeManager", "Kid Mode Disabled")
        return true
    }

    fun verifyPin(pin: String): Boolean {
        val storedHash = prefs.getString(KEY_PIN, null) ?: return false
        return constantTimeEquals(storedHash, hashPin(pin))
    }

    private fun hashPin(pin: String): String {
        val salt = prefs.getString(KEY_SALT, null) ?: newSalt().also {
            prefs.edit().putString(KEY_SALT, it).apply()
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest((salt + pin).toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun newSalt(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) result |= a[i].code xor b[i].code
        return result == 0
    }

    companion object {
        private const val KEY_IS_ENABLED = "is_enabled"
        private const val KEY_PIN = "pin"
        private const val KEY_SALT = "pin_salt"

        // The system prompt to inject when Kid Mode is enabled
        const val SYSTEM_INSTRUCTION = "You are a helpful assistant for an adolescent. Answer innocent educational chats, translations, and code requests with the level of detail appropriate for a 14-year-old. Refer sexually suggestive, violent, or illegal content to a trusted adult."
    }
}
