// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*

fun FragmentActivity.biometric(
    repository: Repository,
    enrollPassword: String? = null,
    done: () -> Unit,
    failure: (String) -> Unit,
) {
    try {
        val cipher = repository.secure.cipher("biometric", true, enrollPassword == null)
        val prompt =
            BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        failure(message.toString())
                    }

                    override fun onAuthenticationSucceeded(
                        result: BiometricPrompt.AuthenticationResult
                    ) {
                        lifecycleScope.launch {
                            try {
                                withContext(Dispatchers.IO) {
                                    val authorized = result.cryptoObject!!.cipher!!
                                    if (enrollPassword != null) {
                                        val bytes = enrollPassword.toByteArray()
                                        try {
                                            repository.secure.save("biometric", bytes, authorized)
                                        } finally {
                                            bytes.fill(0)
                                        }
                                        repository.preferences
                                            .edit()
                                            .putBoolean("biometric", true)
                                            .apply()
                                    } else {
                                        val bytes = repository.secure.read("biometric", authorized)
                                        try {
                                            repository.unlock(String(bytes))
                                        } finally {
                                            bytes.fill(0)
                                        }
                                    }
                                }
                                done()
                            } catch (e: Exception) {
                                failure(
                                    e.message ?: "Biometric unlock failed; use the master password"
                                )
                            }
                        }
                    }
                },
            )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(
                    if (enrollPassword == null) "Unlock Signet" else "Enable biometric unlock"
                )
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
                )
                .setSubtitle("Authenticate to use the vault password")
                .setNegativeButtonText("Cancel")
                .build(),
            BiometricPrompt.CryptoObject(cipher),
        )
    } catch (e: Exception) {
        failure(e.message ?: "Biometric unlock unavailable")
    }
}
