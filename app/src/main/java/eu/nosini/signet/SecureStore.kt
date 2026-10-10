// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import eu.nosini.signet.vault.atomicWrite
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Non-authenticated WebDAV credentials and authenticated biometric password use different keys. */
class SecureStore(private val context: Context) {
    private fun key(alias: String, biometric: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let {
            return it
        }
        val spec =
            KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(biometric)
        if (biometric) {
            spec.setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= 30)
                spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec.build()) }
            .generateKey()
    }

    fun cipher(alias: String, biometric: Boolean, decrypt: Boolean): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            if (decrypt) {
                val data = File(context.filesDir, "$alias.enc").readBytes()
                init(
                    Cipher.DECRYPT_MODE,
                    key(alias, biometric),
                    GCMParameterSpec(128, data.copyOfRange(0, 12)),
                )
            } else init(Cipher.ENCRYPT_MODE, key(alias, biometric))
        }

    fun save(alias: String, plain: ByteArray, cipher: Cipher = cipher(alias, false, false)) {
        require(cipher.iv.size == 12)
        atomicWrite(File(context.filesDir, "$alias.enc"), cipher.iv + cipher.doFinal(plain))
    }

    fun read(alias: String, cipher: Cipher = cipher(alias, false, true)): ByteArray =
        cipher.doFinal(
            File(context.filesDir, "$alias.enc")
                .readBytes()
                .copyOfRange(12, File(context.filesDir, "$alias.enc").length().toInt())
        )

    fun delete(alias: String) {
        File(context.filesDir, "$alias.enc").delete()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }
}
