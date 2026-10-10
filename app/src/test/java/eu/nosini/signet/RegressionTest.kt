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

    @Test
    fun signingSubkeyApprovalUsesPrimaryId() {
        val key = CryptoTest.modern
        val indexed = IndexedKey(Crypto.armor(Crypto.publicPart(key)), true)
        val subkey = indexed.info.signingSubkeys.first().keyIdentifier.keyId
        assertNotEquals(indexed.id, subkey)
        var approvedKey = 0L
        var mode = ""
        handler(listOf(indexed)) { m, k ->
                mode = m
                approvedKey = k
                Intent().putExtra(RESULT_CODE, RESULT_CODE_USER_INTERACTION_REQUIRED)
            }
            .handle(
                request(ACTION_DETACHED_SIGN).putExtra(EXTRA_SIGN_KEY_ID, subkey),
                "data".byteInputStream(),
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals("approve", mode)
        assertEquals(indexed.id, approvedKey)
        assertNotNull(listOf(indexed).find { it.id == approvedKey })
    }

    @Test
    fun signatureResultExcludesUnboundUserIds() {
        val key = CryptoTest.modern
        val public = Crypto.publicPart(key)
        val bytes = public.encoded
        val primary = public.publicKey.publicKeyPacket.encoded
        val extra = org.bouncycastle.bcpg.UserIDPacket("Victim <victim@example.org>").encoded
        val forged = Crypto.publicKey(primary + extra + bytes.copyOfRange(primary.size, bytes.size))
        val indexed = IndexedKey(Crypto.armor(forged), false)
        val signed = ByteArrayOutputStream()
        Crypto.produce("signed message".byteInputStream(), signed, signer = key, cleartext = true)
        val verify =
            handler(listOf(indexed)) { m, _ -> Intent().putExtra("mode", m) }
                .handle(
                    request(ACTION_DECRYPT_VERIFY),
                    signed.toByteArray().inputStream(),
                    ByteArrayOutputStream(),
                    caller,
                )
        val result = verify.getParcelableExtra<OpenPgpSignatureResult>(RESULT_SIGNATURE)!!
        assertEquals(OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED, result.result)
        assertFalse(result.userIds.contains("Victim <victim@example.org>"))
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

    @Test
    fun remoteRollbackKeepsNewerLocalKeys() {
        MockWebServer().use { server ->
            server.start()
            val dir = Files.createTempDirectory("signet-review").toFile()
            try {
                val file = java.io.File(dir, "vault.kdbx")
                val v1 = VaultCodec.put(VaultCodec.create("password"), "AAA", "a", "a", "A", now)
                val v1bytes = v1.bytes()
                file.writeBytes(v1bytes)
                val config = DavConfig(server.url("/vault.kdbx").toString(), "user", "password")
                val dav = WebDav()
                server.enqueue(response(404))
                server.enqueue(response(201, etag = "\"one\""))
                var result = dav.sync(file, v1, config, SyncState())
                val v2 = VaultCodec.put(result.database, "BBB", "b", "b", "B", now.plusSeconds(5))
                file.writeBytes(v2.bytes())
                server.enqueue(response(304))
                server.enqueue(response(204, etag = "\"two\""))
                result = dav.sync(file, v2, config, result.state)
                assertEquals(2, result.database.keyEntries().size)
                // Server (or a restored file version) now serves the first file again.
                server.enqueue(response(200, v1bytes, "\"three\""))
                server.enqueue(response(204, etag = "\"four\""))
                result = dav.sync(file, result.database, config, result.state)
                assertTrue(result.changed)
                assertEquals(2, result.database.keyEntries().size)
                val reread = VaultCodec.read(file.readBytes(), credentials("password"))
                assertEquals(
                    setOf("AAA", "BBB"),
                    reread.keyEntries().map { it.fields[FINGERPRINT]!!.content }.toSet(),
                )
            } finally {
                dir.deleteRecursively()
            }
        }
    }

    @Test
    fun unrelatedRemoteRootIsRejectedWithoutChangingLocalFile() {
        MockWebServer().use { server ->
            server.start()
            val dir = Files.createTempDirectory("signet-root-check").toFile()
            try {
                val file = java.io.File(dir, "vault.kdbx")
                val local = VaultCodec.create("password")
                file.writeBytes(local.bytes())
                val config = DavConfig(server.url("/vault.kdbx").toString())
                val dav = WebDav()
                server.enqueue(response(404))
                server.enqueue(response(201, etag = "\"one\""))
                val synced = dav.sync(file, local, config, SyncState())
                val before = file.readBytes()
                val unrelated = VaultCodec.create("password")
                assertNotEquals(local.content.group.uuid, unrelated.content.group.uuid)
                server.enqueue(response(200, unrelated.bytes(), "\"two\""))
                assertTrue(
                    runCatching { dav.sync(file, synced.database, config, synced.state) }.isFailure
                )
                assertArrayEquals(before, file.readBytes())
            } finally {
                dir.deleteRecursively()
            }
        }
    }

    @Test
    fun historyStaysOldestFirstAcrossMergeAndEdits() {
        val v1 = VaultCodec.put(VaultCodec.create("password"), "AAA", "1", null, "A", now)
        val v2 = VaultCodec.put(v1, "AAA", "2", null, "A", now.plusSeconds(1))
        val v3 = VaultCodec.put(v2, "AAA", "3", null, "A", now.plusSeconds(2))
        val ascending = v3.keyEntries().single().history.map { it.fields[PUBLIC_KEY]!!.content }
        assertEquals(listOf("1", "2"), ascending)
        val remote = VaultCodec.put(v2, "AAA", "r", null, "A", now.plusSeconds(3))
        val merged = VaultMerge.merge(v3, remote)
        val mergedOrder =
            merged.keyEntries().single().history.map { it.fields[PUBLIC_KEY]!!.content }
        val next = VaultCodec.put(merged, "AAA", "4", null, "A", now.plusSeconds(4))
        val nextOrder = next.keyEntries().single().history.map { it.fields[PUBLIC_KEY]!!.content }
        println("history after merge: $mergedOrder; after next edit: $nextOrder")
        assertEquals(listOf("1", "2", "3"), mergedOrder)
        assertEquals(listOf("1", "2", "3", "r"), nextOrder)
    }

}
