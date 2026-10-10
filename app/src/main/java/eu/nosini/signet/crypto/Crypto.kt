// SPDX-License-Identifier: GPL-3.0-or-later
@file:Suppress("DEPRECATION")

package eu.nosini.signet.crypto

import java.io.*
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.*
import org.pgpainless.decryption_verification.*
import org.pgpainless.encryption_signing.*
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.protection.SecretKeyRingProtector

/** PGPainless's lightweight BC implementation never uses Android's bundled BC provider. */
object Crypto {
    val pgp = PGPainless()

    fun publicKey(bytes: ByteArray): PGPPublicKeyRing =
        PGPainless.readKeyRing().publicKeyRing(bytes)!!

    fun publicKey(armor: String): PGPPublicKeyRing = PGPainless.readKeyRing().publicKeyRing(armor)!!

    fun secretKey(armor: String): PGPSecretKeyRing = PGPainless.readKeyRing().secretKeyRing(armor)!!

    fun fingerprint(key: PGPPublicKeyRing): String =
        key.publicKey.fingerprint.joinToString("") { "%02X".format(it) }

    fun publicPart(key: PGPSecretKeyRing): PGPPublicKeyRing = PGPainless.extractCertificate(key)

    fun generate(userId: String, rsa: Boolean = false): PGPSecretKeyRing {
        val key =
            if (rsa) pgp.generateKey().rsaKeyRing(userId, RsaLength._4096)
            else pgp.generateKey().modernKeyRing(userId)
        return secretKey(pgp.toAsciiArmor(key))
    }

    fun unprotect(key: PGPSecretKeyRing, password: String): PGPSecretKeyRing {
        val chars = password.toCharArray()
        try {
            val decryptor =
                BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(chars)
            return PGPSecretKeyRing.copyWithNewPassword(key, decryptor, null)
        } finally {
            chars.fill('\u0000')
        }
    }

    fun protected(key: PGPSecretKeyRing) =
        key.secretKeys.asSequence().any { !it.isPrivateKeyEmpty && it.keyEncryptionAlgorithm != 0 }

    fun armor(key: PGPKeyRing): String = PGPainless.asciiArmor(key)

    fun produce(
        input: InputStream,
        output: OutputStream,
        recipients: List<PGPPublicKeyRing> = emptyList(),
        signer: PGPSecretKeyRing? = null,
        ascii: Boolean = true,
        detached: Boolean = false,
        cleartext: Boolean = false,
        filename: String = "",
        compression: Boolean = true,
    ): ByteArray? {
        val encrypt =
            recipients
                .takeIf { it.isNotEmpty() }
                ?.let { list ->
                    EncryptionOptions.get().also { opts -> list.forEach { opts.addRecipient(it) } }
                }
        val sign = signer?.let {
            SigningOptions.get().also { opts ->
                if (detached || cleartext)
                    opts.addDetachedSignature(
                        SecretKeyRingProtector.unprotectedKeys(),
                        it,
                        if (cleartext) DocumentSignatureType.CANONICAL_TEXT_DOCUMENT
                        else DocumentSignatureType.BINARY_DOCUMENT,
                    )
                else
                    opts.addInlineSignature(
                        SecretKeyRingProtector.unprotectedKeys(),
                        it,
                        DocumentSignatureType.BINARY_DOCUMENT,
                    )
            }
        }
        val options =
            when {
                encrypt != null && sign != null -> ProducerOptions.signAndEncrypt(encrypt, sign)
                encrypt != null -> ProducerOptions.encrypt(encrypt)
                sign != null -> ProducerOptions.sign(sign)
                else -> error("Select recipients or a signing key")
            }
        options.setAsciiArmor(ascii).setFileName(filename)
        if (!compression) options.overrideCompressionAlgorithm(CompressionAlgorithm.UNCOMPRESSED)
        if (cleartext) options.setCleartextSigned()
        val stream = pgp.generateMessage().onOutputStream(output).withOptions(options)
        stream.use { input.copyTo(it) }
        return stream.result.detachedSignatures.values.firstOrNull()?.let { signatures ->
            signatures.firstOrNull()?.let {
                if (ascii) PGPainless.asciiArmor(it).toByteArray() else it.encoded
            }
        }
    }

    fun consume(
        input: InputStream,
        output: OutputStream,
        certificates: List<PGPPublicKeyRing>,
        secrets: List<PGPSecretKeyRing> = emptyList(),
        detached: ByteArray? = null,
    ): MessageMetadata {
        val options = ConsumerOptions.get()
        certificates.forEach { options.addVerificationCert(it) }
        secrets.forEach { options.addDecryptionKey(it, SecretKeyRingProtector.unprotectedKeys()) }
        detached?.let { options.addVerificationOfDetachedSignatures(it.inputStream()) }
        val stream = pgp.processMessage().onInputStream(input).withOptions(options)
        stream.use { it.copyTo(output) }
        return stream.metadata
    }
}
