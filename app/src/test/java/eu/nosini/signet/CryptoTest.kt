// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import eu.nosini.signet.crypto.Crypto
import java.io.ByteArrayOutputStream
import org.bouncycastle.openpgp.*
import org.junit.Assert.*
import org.junit.Test
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.util.Passphrase

class CryptoTest {
    companion object {
        val modern by lazy { Crypto.generate("Ed Test <ed@example.org>") }
        val rsa by lazy {
            Crypto.secretKey(
                Crypto.pgp.toAsciiArmor(
                    Crypto.pgp
                        .generateKey()
                        .rsaKeyRing("RSA Test <rsa@example.org>", RsaLength._2048)
                )
            )
        }
    }

    @Test
    fun operationsForBothKeyTypes() {
        for (key in listOf(modern, rsa)) {
            val public = Crypto.publicPart(key)
            val message = "Hello Signet\nsecond line\n".toByteArray()
            for (mode in listOf("sign", "encrypt", "both", "detached", "cleartext")) {
                val out = ByteArrayOutputStream()
                val signature =
                    Crypto.produce(
                        message.inputStream(),
                        out,
                        if (mode in listOf("encrypt", "both")) listOf(public) else emptyList(),
                        if (mode == "encrypt") null else key,
                        detached = mode == "detached",
                        cleartext = mode == "cleartext",
                    )
                val plain = ByteArrayOutputStream()
                val metadata =
                    Crypto.consume(
                        (if (mode == "detached") message else out.toByteArray()).inputStream(),
                        plain,
                        listOf(public),
                        if (mode in listOf("encrypt", "both")) listOf(key) else emptyList(),
                        if (mode == "detached") signature else null,
                    )
                assertEquals(mode in listOf("encrypt", "both"), metadata.isEncrypted)
                if (mode != "encrypt") assertTrue("$mode signature", metadata.isVerifiedSigned())
                assertEquals(String(message).trim(), plain.toString().replace("\r", "").trim())
            }
        }
    }

    @Test
    fun protectedImportIsUnprotected() {
        val protected =
            Crypto.secretKey(
                Crypto.pgp.toAsciiArmor(
                    Crypto.pgp
                        .generateKey()
                        .modernKeyRing(
                            "Protected <protected@example.org>",
                            Passphrase.fromPassword("test-passphrase"),
                        )
                )
            )
        assertTrue(Crypto.protected(protected))
        val unlocked = Crypto.unprotect(protected, "test-passphrase")
        assertFalse(Crypto.protected(Crypto.secretKey(Crypto.armor(unlocked))))
        assertEquals(
            Crypto.fingerprint(Crypto.publicPart(protected)),
            Crypto.fingerprint(Crypto.publicPart(unlocked)),
        )
    }

    @Test
    fun tamperedSignatureDoesNotVerify() {
        val public = Crypto.publicPart(modern)
        val signature =
            Crypto.produce(
                "original".byteInputStream(),
                ByteArrayOutputStream(),
                signer = modern,
                detached = true,
            )!!
        val metadata =
            Crypto.consume(
                "changed".byteInputStream(),
                ByteArrayOutputStream(),
                listOf(public),
                detached = signature,
            )
        assertFalse(metadata.isVerifiedSigned())
    }
}
