// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import eu.nosini.signet.crypto.Crypto
import java.io.*
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class GpgInteropTest {
    private fun resource(name: String) =
        javaClass.getResourceAsStream("/gpg/$name")!!.use { it.readBytes() }

    @Test
    fun gpgMessagesAreCompatible() {
        val secret = Crypto.secretKey(String(resource("secret.asc")))
        val public = Crypto.publicKey(String(resource("public.asc")))
        val plain = ByteArrayOutputStream()
        assertTrue(
            Crypto.consume(
                    resource("encrypted.asc").inputStream(),
                    plain,
                    listOf(public),
                    listOf(secret),
                )
                .isEncrypted
        )
        assertArrayEquals(resource("message.txt"), plain.toByteArray())
        assertTrue(
            Crypto.consume(
                    resource("signed.asc").inputStream(),
                    ByteArrayOutputStream(),
                    listOf(public),
                )
                .isVerifiedSigned()
        )
        assertTrue(
            Crypto.consume(
                    resource("message.txt").inputStream(),
                    ByteArrayOutputStream(),
                    listOf(public),
                    detached = resource("signature.asc"),
                )
                .isVerifiedSigned()
        )
    }

    @Test
    fun gpgVerifiesAndDecryptsSignetOutput() {
        assumeTrue(File("/usr/bin/gpg").exists())
        val dir = Files.createTempDirectory("signet-gpg").toFile()
        dir.setReadable(false, false)
        dir.setWritable(false, false)
        dir.setExecutable(false, false)
        dir.setReadable(true, true)
        dir.setWritable(true, true)
        dir.setExecutable(true, true)
        fun run(args: List<String>, bytes: ByteArray = ByteArray(0)): ByteArray {
            val process =
                ProcessBuilder(
                        listOf(
                            "/usr/bin/gpg",
                            "--homedir",
                            dir.path,
                            "--batch",
                            "--pinentry-mode",
                            "loopback",
                            "--passphrase",
                            "",
                        ) + args
                    )
                    .redirectError(File(dir, "gpg.log"))
                    .start()
            process.outputStream.use { it.write(bytes) }
            val result = process.inputStream.use { it.readBytes() }
            assertEquals(File(dir, "gpg.log").readText(), 0, process.waitFor())
            return result
        }
        try {
            run(listOf("--import"), resource("secret.asc"))
            val secret = Crypto.secretKey(String(resource("secret.asc")))
            val public = Crypto.publicPart(secret)
            val encrypted = ByteArrayOutputStream()
            Crypto.produce(resource("message.txt").inputStream(), encrypted, listOf(public), secret)
            assertArrayEquals(
                resource("message.txt"),
                run(listOf("--decrypt"), encrypted.toByteArray()),
            )
            val sig =
                Crypto.produce(
                    resource("message.txt").inputStream(),
                    ByteArrayOutputStream(),
                    signer = secret,
                    detached = true,
                )!!
            File(dir, "signature.asc").writeBytes(sig)
            File(dir, "message.txt").writeBytes(resource("message.txt"))
            run(listOf("--verify", File(dir, "signature.asc").path, File(dir, "message.txt").path))
        } finally {
            ProcessBuilder("gpgconf", "--homedir", dir.path, "--kill", "gpg-agent")
                .start()
                .waitFor()
            dir.deleteRecursively()
        }
    }
}
