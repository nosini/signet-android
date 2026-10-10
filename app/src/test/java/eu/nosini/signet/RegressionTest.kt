// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.Intent
import app.keemobile.kotpass.database.*
import app.keemobile.kotpass.models.*
import eu.nosini.signet.api.*
import eu.nosini.signet.crypto.Crypto
import eu.nosini.signet.vault.*
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.time.Instant
import java.util.UUID
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.*
import org.openintents.openpgp.util.OpenPgpApi.*
import org.pgpainless.PGPainless
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = android.app.Application::class)
class RegressionProviderTest {
    private val caller = Caller(1000, listOf(CallerApp("test.app", setOf("cert"), "Test")))
    private val registrations =
        object : Registrations {
            override fun registered(caller: Caller) = true

            override fun register(caller: Caller) {}

            override fun revoke(packageName: String) {}

            override fun list() = emptyMap<String, Set<String>>()
        }

    private fun request(action: String) = Intent(action).putExtra(EXTRA_API_VERSION, 11)

    private fun handler(keys: List<IndexedKey>, interaction: (String, Long) -> Intent) =
        OpenPgpRequestHandler(
            object : KeyBackend {
                override val unlocked = true

                override fun keys() = keys

                override fun secret(id: Long): org.bouncycastle.openpgp.PGPSecretKeyRing? = null

                override fun updatePeer(
                    caller: Caller,
                    address: String,
                    bytes: ByteArray,
                    date: Long,
                ) {}
            },
            registrations,
            Approvals { 0L },
        ) { mode, _, _, key ->
            interaction(mode, key)
        }

    @Test
    fun autocryptPeersAreBoundToTheirAddressAndCaller() {
        val attacker = Crypto.generate("Mallory <mallory@evil.example>")
        @Suppress("DEPRECATION")
        val twoIds =
            PGPainless.modifyKeyRing(attacker)
                .addUserId("Bob <bob@corp.example>", SecretKeyRingProtector.unprotectedKeys())
                .done()
                .pgpSecretKeyRing
        val public = Crypto.publicPart(twoIds)
        val repo = Repository(RuntimeEnvironment.getApplication())
        repo.updatePeer(caller, "MALLORY@evil.example", public.encoded, Long.MAX_VALUE)
        val peer = repo.peers(caller).single()
        assertEquals("mallory@evil.example", peer.peerAddress)
        assertTrue(repo.keys().isEmpty())
        assertTrue(
            repo
                .peers(Caller(2000, listOf(CallerApp("other.app", setOf("other"), "Other"))))
                .isEmpty()
        )
        val resolve = handler(listOf(peer)) { mode, _ -> Intent().putExtra("mode", mode) }
        val wrong =
            resolve.handle(
                request(ACTION_GET_KEY_IDS).putExtra(EXTRA_USER_IDS, arrayOf("bob@corp.example")),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals("recipient-picker", wrong.getStringExtra("mode"))
        val right =
            resolve.handle(
                request(ACTION_GET_KEY_IDS)
                    .putExtra(EXTRA_USER_IDS, arrayOf("mallory@evil.example")),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        assertArrayEquals(longArrayOf(peer.id), right.getLongArrayExtra(RESULT_KEY_IDS))
        val status =
            resolve.handle(
                request(ACTION_QUERY_AUTOCRYPT_STATUS)
                    .putExtra(EXTRA_USER_IDS, arrayOf("bob@corp.example")),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals(AUTOCRYPT_STATUS_UNAVAILABLE, status.getIntExtra(RESULT_AUTOCRYPT_STATUS, -1))
        val encrypted =
            resolve.handle(
                request(ACTION_ENCRYPT)
                    .putExtra(EXTRA_USER_IDS, arrayOf("bob@corp.example"))
                    .putExtra(EXTRA_OPPORTUNISTIC_ENCRYPTION, true),
                "hello bob".byteInputStream(),
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals(RESULT_CODE_ERROR, encrypted.getIntExtra(RESULT_CODE, -1))
        // A future timestamp was clamped, and a case variant shares the chronology.
        val older = Crypto.publicPart(Crypto.generate("Older <mallory@evil.example>"))
        repo.updatePeer(caller, "mallory@EVIL.example", older.encoded, 0L)
        assertEquals(peer.fingerprint, repo.peers(caller).single().fingerprint)
    }

}

class RegressionVaultTest {
    private val now = Instant.parse("2026-10-10T12:00:00Z")

    private fun response(code: Int, bytes: ByteArray? = null, etag: String? = null) =
        MockResponse.Builder()
            .code(code)
            .apply {
                bytes?.let { body(Buffer().write(it)) }
                etag?.let { addHeader("ETag", it) }
            }
            .build()

}
