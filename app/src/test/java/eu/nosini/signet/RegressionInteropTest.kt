// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.Intent
import eu.nosini.signet.api.*
import eu.nosini.signet.crypto.Crypto
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.util.OpenPgpApi.*
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = android.app.Application::class)
class RegressionInteropTest {
    private val caller = Caller(1000, listOf(CallerApp("test.app", setOf("cert"), "Test")))

    private fun handler(keys: List<IndexedKey>) =
        OpenPgpRequestHandler(
            object : KeyBackend {
                override val unlocked = false

                override fun keys() = keys

                override fun secret(id: Long): org.bouncycastle.openpgp.PGPSecretKeyRing? = null

                override fun updatePeer(
                    caller: Caller,
                    address: String,
                    bytes: ByteArray,
                    date: Long,
                ) {}
            },
            object : Registrations {
                override fun registered(caller: Caller) = true

                override fun register(caller: Caller) {}

                override fun revoke(packageName: String) {}

                override fun list() = emptyMap<String, Set<String>>()
            },
            Approvals { 0L },
        ) { mode, _, _, _ ->
            Intent().putExtra("mode", mode)
        }

    /** Thunderbird's Autocrypt helper calls GET_KEY without EXTRA_REQUEST_ASCII_ARMOR. */
    @Test
    fun getKeyDefaultsToBinarySupportsAddressAndMinimize() {
        @Suppress("DEPRECATION")
        val key =
            org.pgpainless.PGPainless.modifyKeyRing(CryptoTest.modern)
                .addUserId(
                    "Second <second@example.org>",
                    org.pgpainless.key.protection.SecretKeyRingProtector.unprotectedKeys(),
                )
                .done()
                .pgpSecretKeyRing
        val indexed = IndexedKey(Crypto.armor(Crypto.publicPart(key)), true)
        val out = ByteArrayOutputStream()
        val result =
            handler(listOf(indexed))
                .handle(
                    Intent(ACTION_GET_KEY)
                        .putExtra(EXTRA_API_VERSION, 11)
                        .putExtra(EXTRA_KEY_ID, indexed.id)
                        .putExtra(EXTRA_MINIMIZE, true)
                        .putExtra(EXTRA_MINIMIZE_USER_ID, "ed@example.org"),
                    null,
                    out,
                    caller,
                )
        assertEquals(RESULT_CODE_SUCCESS, result.getIntExtra(RESULT_CODE, -1))
        assertFalse(String(out.toByteArray()).startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        assertEquals(indexed.fingerprint, Crypto.fingerprint(Crypto.publicKey(out.toByteArray())))
        assertEquals(
            listOf("Ed Test <ed@example.org>"),
            Crypto.publicKey(out.toByteArray()).publicKey.userIDs.asSequence().toList(),
        )
        val byUser =
            handler(listOf(indexed))
                .handle(
                    Intent(ACTION_GET_KEY)
                        .putExtra(EXTRA_API_VERSION, 11)
                        .putExtra(EXTRA_USER_ID, "ed@example.org"),
                    null,
                    ByteArrayOutputStream(),
                    caller,
                )
        assertEquals(RESULT_CODE_SUCCESS, byUser.getIntExtra(RESULT_CODE, -1))
    }

    /** Android imports and uses a subkey-only export (GNU dummy primary). */
    @Test
    fun subkeyOnlyExportWorksOnAndroid() {
        assumeTrue(File("/usr/bin/gpg").exists())
        val dir = Files.createTempDirectory("signet-review-gpg").toFile()
        dir.setReadable(false, false)
        dir.setWritable(false, false)
        dir.setExecutable(false, false)
        dir.setReadable(true, true)
        dir.setWritable(true, true)
        dir.setExecutable(true, true)
        fun run(vararg args: String): ByteArray {
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
            process.outputStream.close()
            val result = process.inputStream.use { it.readBytes() }
            assertEquals(File(dir, "gpg.log").readText(), 0, process.waitFor())
            return result
        }
        try {
            run("--quick-gen-key", "Stub <stub@example.org>", "ed25519", "cert", "never")
            val fpr =
                String(run("--with-colons", "--list-keys"))
                    .lines()
                    .first { it.startsWith("fpr:") }
                    .split(':')[9]
            run("--quick-add-key", fpr, "ed25519", "sign", "never")
            val armored = String(run("--armor", "--export-secret-subkeys", fpr))
            val ring = Crypto.secretKey(armored)
            assertFalse(Crypto.protected(ring))
            val sig =
                Crypto.produce(
                    "data".byteInputStream(),
                    ByteArrayOutputStream(),
                    signer = ring,
                    detached = true,
                )
            assertNotNull(sig)
        } finally {
            ProcessBuilder("gpgconf", "--homedir", dir.path, "--kill", "gpg-agent")
                .start()
                .waitFor()
            dir.deleteRecursively()
        }
    }
}
