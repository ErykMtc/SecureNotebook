package com.example.projekt

import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {
    private lateinit var notesEditText: EditText
    private lateinit var saveButton: Button
    private lateinit var loadButton: Button
    private lateinit var exportButton: Button
    private lateinit var importButton: Button
    private lateinit var clearButton: Button

    private val keysetName = "master_keyset"
    private val keysetPrefFile = "master_key_preference"
    private val keyUri = "android-keystore://master_key"
    private lateinit var aead: Aead

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        notesEditText = findViewById(R.id.notesEditText)
        saveButton = findViewById(R.id.saveButton)
        loadButton = findViewById(R.id.loadButton)
        exportButton = findViewById(R.id.exportButton)
        importButton = findViewById(R.id.importButton)
        clearButton = findViewById(R.id.clearButton)

        // Init Tink
        AeadConfig.register()
        val keysetHandle = getKeysetHandle()
        aead = keysetHandle.getPrimitive(Aead::class.java)

        saveButton.setOnClickListener { authenticate { saveNotes() } }
        loadButton.setOnClickListener { authenticate { loadNotes() } }
        exportButton.setOnClickListener { authenticate { showPasswordDialog(true) } }
        importButton.setOnClickListener { authenticate { showPasswordDialog(false) } }
        clearButton.setOnClickListener { authenticate { clearNotes() } }

        // Disable screenshots and prevent content from appearing in recent screen
        window.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE
        )

        // Check for root or Frida
        if (isDeviceRooted() || isFridaServerRunning()) {
            Toast.makeText(this, "Twoje urządzenie nie jest bezpieczne bo sussy baka jest na telefonie", Toast.LENGTH_LONG).show()
            Log.d("BAM", "Twoje urządzenie nie jest bezpieczne bo sussy baka jest na telefonie")
        }
    }

    private fun getKeysetHandle(): KeysetHandle {
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(this, keysetName, keysetPrefFile)
            .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
            .withMasterKeyUri(keyUri)
            .build()
            .keysetHandle

        return keysetHandle
    }

    private fun authenticate(onSuccess: () -> Unit) {
        val executor = Executors.newSingleThreadExecutor()
        val biometricPrompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                runOnUiThread { Toast.makeText(applicationContext, "Authentication error: $errString", Toast.LENGTH_SHORT).show() }
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                runOnUiThread { onSuccess() }
            }

            override fun onAuthenticationFailed() {
                runOnUiThread { Toast.makeText(applicationContext, "Authentication failed", Toast.LENGTH_SHORT).show() }
            }
        })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric authentication")
            .setSubtitle("Authenticate to proceed")
            .setDeviceCredentialAllowed(true)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun showPasswordDialog(isExport: Boolean) {
        val passwordEditText = EditText(this)
        val dialogBuilder = AlertDialog.Builder(this)
            .setTitle(if (isExport) "Enter password to export" else "Enter password to import")
            .setView(passwordEditText)
            .setPositiveButton("OK") { _, _ ->
                val password = passwordEditText.text.toString()
                if (isExport) {
                    exportNotes(password)
                } else {
                    importNotes(password)
                }
            }
            .setNegativeButton("Cancel", null)
        dialogBuilder.show()
    }

    private fun saveNotes() {
        val notes = notesEditText.text.toString()
        if (notes.isNotEmpty()) {
            val encryptedNotes = aead.encrypt(notes.toByteArray(StandardCharsets.UTF_8), null)
            val fos = openFileOutput("notes.txt", Context.MODE_PRIVATE)
            fos.write(encryptedNotes)
            fos.close()
            Toast.makeText(this, "Notes saved securely", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Notes cannot be empty", Toast.LENGTH_SHORT).show()
        }
    }

    private fun loadNotes() {
        try {
            val fis = openFileInput("notes.txt")
            val encryptedNotes = fis.readBytes()
            fis.close()
            val decryptedNotes = aead.decrypt(encryptedNotes, null)
            notesEditText.setText(String(decryptedNotes, StandardCharsets.UTF_8))
            Toast.makeText(this, "Notes loaded successfully", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to load notes: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun exportNotes(password: String) {
        val notes = notesEditText.text.toString()
        if (notes.isNotEmpty()) {
            val encryptedNotes = encryptWithPassword(notes.toByteArray(StandardCharsets.UTF_8), password)
            val exportFile = File(getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS), "exported_notes.txt")
            val fos = FileOutputStream(exportFile)
            fos.write(encryptedNotes)
            fos.close()
            Toast.makeText(this, "Notes exported securely", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Notes cannot be empty", Toast.LENGTH_SHORT).show()
        }
    }

    private fun importNotes(password: String) {
        val importFile = File(getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS), "exported_notes.txt")
        if (importFile.exists()) {
            val fis = FileInputStream(importFile)
            val encryptedNotes = fis.readBytes()
            fis.close()
            try {
                val decryptedNotes = decryptWithPassword(encryptedNotes, password)
                notesEditText.setText(String(decryptedNotes, StandardCharsets.UTF_8))
                Toast.makeText(this, "Notes imported successfully", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Incorrect password or corrupted file", Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(this, "No exported notes found", Toast.LENGTH_SHORT).show()
        }
    }

    private fun clearNotes() {
        deleteFile("notes.txt")
        val sharedPrefs = getSharedPreferences(keysetPrefFile, Context.MODE_PRIVATE)
        sharedPrefs.edit().clear().apply()
        Toast.makeText(this, "Notes and keys cleared", Toast.LENGTH_SHORT).show()
    }

    private fun isDeviceRooted(): Boolean {
        val superuserApk = File("/system/app/Supperuser.apk")
        val suBinary = File("/system/bin/su")

        return superuserApk.exists() || suBinary.exists()
    }

    private fun isFridaServerRunning(): Boolean {
        val fridaProcesses = listOf("frida-server", "frida-server-12")
        return fridaProcesses.any { processName ->
            try {
                Runtime.getRuntime().exec("pgrep $processName").waitFor() == 0
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun generateKeyFromPassword(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec: KeySpec = PBEKeySpec(password.toCharArray(), salt, 65536, 256)
        val tmp = factory.generateSecret(spec)
        return SecretKeySpec(tmp.encoded, "AES")
    }

    private fun encryptWithPassword(data: ByteArray, password: String): ByteArray {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        val key = generateKeyFromPassword(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val cipherText = cipher.doFinal(data)
        return salt + iv + cipherText
    }

    private fun decryptWithPassword(encryptedData: ByteArray, password: String): ByteArray {
        val salt = encryptedData.copyOfRange(0, 16)
        val iv = encryptedData.copyOfRange(16, 28)
        val cipherText = encryptedData.copyOfRange(28, encryptedData.size)
        val key = generateKeyFromPassword(password, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher.doFinal(cipherText)
    }
}