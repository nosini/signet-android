// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.app.Application
import android.content.Intent
import app.keemobile.kotpass.database.*
import app.keemobile.kotpass.models.*
import eu.nosini.signet.api.*
import eu.nosini.signet.crypto.Crypto
import eu.nosini.signet.vault.*
import java.io.ByteArrayOutputStream
import java.time.Duration
import java.time.Instant
import java.util.UUID
import java.util.concurrent.*
import mockwebserver3.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.util.OpenPgpApi.*
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class FollowupTest {
    private val caller = Caller(1000, listOf(CallerApp("review.app", setOf("cert"), "Review")))

    @Test
    fun importedKeyAlsoReceivedThroughAutocryptRemainsResolvable() {
        val repo = Repository(RuntimeEnvironment.getApplication())
        repo.create("password")
        val public = Crypto.publicPart(CryptoTest.modern)
        repo.importKey(Crypto.armor(public))
        repo.updatePeer(caller, "ed@example.org", public.encoded, System.currentTimeMillis())
        repo.registrations.register(caller)
        val handler =
            OpenPgpRequestHandler(
                object : KeyBackend {
                    override fun keys() = repo.keys()

                    override fun peers(caller: Caller) = repo.peers(caller)

                    override val unlocked
                        get() = repo.unlocked

                    override fun secret(id: Long) = repo.secret(id)

                    override fun updatePeer(
                        caller: Caller,
                        address: String,
                        bytes: ByteArray,
                        date: Long,
                    ) = repo.updatePeer(caller, address, bytes, date)
                },
                repo.registrations,
                repo.approvals,
            ) { mode, _, _, _ ->
                Intent()
                    .putExtra(RESULT_CODE, RESULT_CODE_USER_INTERACTION_REQUIRED)
                    .putExtra("mode", mode)
            }
        fun request(action: String) =
            Intent(action)
                .putExtra(EXTRA_API_VERSION, 11)
                .putExtra(EXTRA_USER_IDS, arrayOf("ed@example.org"))
        val ids = handler.handle(request(ACTION_GET_KEY_IDS), null, ByteArrayOutputStream(), caller)
        val status =
            handler.handle(
                request(ACTION_QUERY_AUTOCRYPT_STATUS),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        val encrypt =
            handler.handle(
                request(ACTION_ENCRYPT).putExtra(EXTRA_OPPORTUNISTIC_ENCRYPTION, true),
                "hello".byteInputStream(),
                ByteArrayOutputStream(),
                caller,
            )
        val get =
            handler.handle(
                request(ACTION_GET_KEY).putExtra(EXTRA_USER_ID, "ed@example.org"),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        println(
            "vault=${repo.keys().size} peers=${repo.peers(caller).size} sameFingerprint=${repo.keys().single().fingerprint == repo.peers(caller).single().fingerprint}"
        )
        println(
            "idsCode=${ids.getIntExtra(RESULT_CODE, -1)} mode=${ids.getStringExtra("mode")} status=${status.getIntExtra(RESULT_AUTOCRYPT_STATUS, -1)} encryptCode=${encrypt.getIntExtra(RESULT_CODE, -1)} getCode=${get.getIntExtra(RESULT_CODE, -1)}"
        )
        assertArrayEquals(
            longArrayOf(public.publicKey.keyID),
            ids.getLongArrayExtra(RESULT_KEY_IDS),
        )
        assertEquals(AUTOCRYPT_STATUS_AVAILABLE, status.getIntExtra(RESULT_AUTOCRYPT_STATUS, -1))
        assertEquals(RESULT_CODE_SUCCESS, encrypt.getIntExtra(RESULT_CODE, -1))
        assertEquals(RESULT_CODE_SUCCESS, get.getIntExtra(RESULT_CODE, -1))
        assertEquals(
            "A single certificate is not ambiguous",
            RESULT_CODE_SUCCESS,
            ids.getIntExtra(RESULT_CODE, -1),
        )
    }

    @Test
    fun sharedPeerCertificateStillResolvesEachOfItsBoundAddresses() {
        @Suppress("DEPRECATION")
        val ring =
            org.pgpainless.PGPainless.modifyKeyRing(CryptoTest.modern)
                .addUserId(
                    "Other <other@example.org>",
                    org.pgpainless.key.protection.SecretKeyRingProtector.unprotectedKeys(),
                )
                .done()
                .pgpSecretKeyRing
        val public = Crypto.publicPart(ring)
        val repo = Repository(RuntimeEnvironment.getApplication())
        for (address in listOf("ed@example.org", "other@example.org")) {
            repo.updatePeer(caller, address, public.encoded, System.currentTimeMillis())
        }
        repo.registrations.register(caller)
        val handler =
            OpenPgpRequestHandler(
                object : KeyBackend {
                    override fun keys() = repo.keys()

                    override fun peers(caller: Caller) = repo.peers(caller)

                    override val unlocked
                        get() = repo.unlocked

                    override fun secret(id: Long) = repo.secret(id)

                    override fun updatePeer(
                        caller: Caller,
                        address: String,
                        bytes: ByteArray,
                        date: Long,
                    ) = repo.updatePeer(caller, address, bytes, date)
                },
                repo.registrations,
                repo.approvals,
            ) { mode, _, _, _ ->
                Intent().putExtra("mode", mode)
            }
        assertEquals(2, repo.peers(caller).size)
        for (address in listOf("ed@example.org", "other@example.org")) {
            val ids =
                handler.handle(
                    Intent(ACTION_GET_KEY_IDS)
                        .putExtra(EXTRA_API_VERSION, 11)
                        .putExtra(EXTRA_USER_IDS, arrayOf(address)),
                    null,
                    ByteArrayOutputStream(),
                    caller,
                )
            assertEquals(RESULT_CODE_SUCCESS, ids.getIntExtra(RESULT_CODE, -1))
            assertArrayEquals(
                longArrayOf(public.publicKey.keyID),
                ids.getLongArrayExtra(RESULT_KEY_IDS),
            )
            val out = ByteArrayOutputStream()
            val get =
                handler.handle(
                    Intent(ACTION_GET_KEY)
                        .putExtra(EXTRA_API_VERSION, 11)
                        .putExtra(EXTRA_USER_ID, address),
                    null,
                    out,
                    caller,
                )
            assertEquals(RESULT_CODE_SUCCESS, get.getIntExtra(RESULT_CODE, -1))
            assertEquals(
                Crypto.fingerprint(public),
                Crypto.fingerprint(Crypto.publicKey(out.toByteArray())),
            )
        }
    }

    @Test
    fun queuedUnlockMustNotUndoALaterLock() {
        MockWebServer().use { server ->
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        if (request.method == "GET") {
                            started.countDown()
                            check(release.await(20, TimeUnit.SECONDS))
                            return MockResponse.Builder().code(404).build()
                        }
                        return MockResponse.Builder().code(204).build()
                    }
                }
            server.start()
            val repo =
                Repository(RuntimeEnvironment.getApplication()) {
                    DavConfig(server.url("/vault").toString())
                }
            repo.create("password")
            val executor = Executors.newSingleThreadExecutor()
            val sync = executor.submit<Unit> { repo.sync() }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            repo.lock() // User locks during sync, then starts an unlock before a second screen-off.
            var failure: Throwable? = null
            val queued = Thread {
                try {
                    repo.unlock("password")
                } catch (e: Throwable) {
                    failure = e
                }
            }
            queued.start()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (queued.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread
                .sleep(5)
            assertEquals(Thread.State.BLOCKED, queued.state)
            repo.lock()
            assertFalse(repo.unlocked)
            release.countDown()
            sync.get(10, TimeUnit.SECONDS)
            queued.join(10_000)
            executor.shutdownNow()
            val reopened = repo.unlocked
            println(
                "queuedUnlockFinished=${!queued.isAlive} failure=$failure unlockedAfterLock=$reopened"
            )
            repo.lock()
            assertNotNull("Cancelled unlock must report failure", failure)
            assertFalse(queued.isAlive)
            assertFalse("An unlock already queued before lock must not re-open the vault", reopened)
        }
    }

    @Test
    fun unlockCallbackInitiatedBeforeLockCannotAdoptANewEpoch() {
        val repo = Repository(RuntimeEnvironment.getApplication())
        repo.create("password")
        repo.lock()
        val attempt = repo.sessionEpoch
        repo.lock()
        assertTrue(runCatching { repo.unlock("password", attempt) }.isFailure)
        assertFalse(repo.unlocked)
        repo.unlock("password")
        assertTrue(repo.unlocked)
        repo.lock()
    }

    @Test
    fun passwordCheckWhileUnlockedSkipsTheKdfButStillRejectsWrongPasswords() {
        val repo = Repository(RuntimeEnvironment.getApplication())
        val password = "pässwörd ✓"
        repo.create(password)
        repo.lock()
        repo.unlock(password)
        // Without the vault file, only the in-memory comparison can succeed.
        val moved = java.io.File(repo.file.path + ".moved")
        assertTrue(repo.file.renameTo(moved))
        try {
            repo.checkPassword(password)
            assertTrue(runCatching { repo.checkPassword("pässwörd") }.isFailure)
            assertTrue(runCatching { repo.checkPassword("") }.isFailure)
        } finally {
            assertTrue(moved.renameTo(repo.file))
        }
        repo.lock()
        repo.checkPassword(password)
        assertTrue(runCatching { repo.checkPassword("pässwörd") }.isFailure)
    }

    @Test
    fun staleProtectedKeyUnlockCannotPopulateAReopenedSession() {
        val protected =
            Crypto.secretKey(
                Crypto.pgp.toAsciiArmor(
                    Crypto.pgp
                        .generateKey()
                        .modernKeyRing(
                            "Protected <protected@example.org>",
                            org.pgpainless.util.Passphrase.fromPassword("key-password"),
                        )
                )
            )
        val public = Crypto.publicPart(protected)
        val database =
            VaultCodec.put(
                VaultCodec.create("password"),
                Crypto.fingerprint(public),
                publicKey = Crypto.armor(public),
                privateKey = Crypto.armor(protected),
                title = "Protected",
            )
        val repo = Repository(RuntimeEnvironment.getApplication())
        repo.open(database.bytes())
        repo.unlock("password")
        val attempt = repo.sessionEpoch
        repo.lock()
        repo.unlock("password")
        val id = public.publicKey.keyID
        assertTrue(runCatching { repo.unlockProtected(id, "key-password", attempt) }.isFailure)
        assertTrue(Crypto.protected(repo.secret(id)!!))
        repo.unlockProtected(id, "key-password")
        assertFalse(Crypto.protected(repo.secret(id)!!))
        repo.lock()
    }

    @Test
    fun alwaysAllowIsStoredOnlyWithAValidApprovalAndSurvivesLocking() {
        val repo = Repository(RuntimeEnvironment.getApplication())
        repo.open(VaultCodec.create("password").bytes())
        val caller = Caller(1000, listOf(CallerApp("test.app", setOf("cert"), "Test")))
        val grant = Grant("decrypt", "F1")
        repo.unlock("password")
        // An unregistered app gets neither a token nor a grant.
        assertTrue(
            runCatching { repo.approve(caller, ACTION_DECRYPT_VERIFY, 1, 0, repo.sessionEpoch, grant) }
                .isFailure
        )
        assertFalse(repo.grants.allowed(caller, "decrypt", "F1"))
        repo.registrations.register(caller)
        val stale = repo.sessionEpoch
        repo.lock()
        repo.unlock("password")
        assertTrue(
            runCatching { repo.approve(caller, ACTION_DECRYPT_VERIFY, 1, 0, stale, grant) }.isFailure
        )
        assertFalse(repo.grants.allowed(caller, "decrypt", "F1"))
        repo.approve(caller, ACTION_DECRYPT_VERIFY, 1, 0, repo.sessionEpoch, grant)
        repo.lock()
        assertTrue(repo.grants.allowed(caller, "decrypt", "F1"))
        assertFalse(repo.grants.allowed(caller, "sign", "F1"))
        repo.grants.revokeApp("test.app")
        repo.registrations.revoke("test.app")
    }

    @Test
    fun periodicSyncMustNotStopIdleLockTimer() {
        MockWebServer().use { server ->
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        if (request.method == "GET") {
                            started.countDown()
                            check(release.await(40, TimeUnit.SECONDS))
                            return MockResponse.Builder().code(404).build()
                        }
                        return MockResponse.Builder().code(204).build()
                    }
                }
            server.start()
            // Model a device that has been up long enough for lastSync=0 to be due.
            ShadowSystemClock.advanceBy(Duration.ofMinutes(6))
            val repo =
                Repository(RuntimeEnvironment.getApplication()) {
                    DavConfig(server.url("/vault").toString())
                }
            repo.preferences.edit().putLong("lock-minutes", 1).putLong("sync-minutes", 5).commit()
            repo.create("password")
            try {
                assertTrue("Real periodic loop starts sync", started.await(15, TimeUnit.SECONDS))
                ShadowSystemClock.advanceBy(Duration.ofMinutes(2))
                Thread.sleep(12_000)
                println("afterIdleDeadlineAndAnotherTick unlocked=${repo.unlocked}")
                assertFalse(
                    "Idle timer must lock while its periodic sync is stalled",
                    repo.unlocked,
                )
            } finally {
                repo.lock()
                release.countDown()
            }
        }
    }

    @Test
    fun linuxFixtureWithAbsentTimesConvergesOnAndroidToo() {
        fun read(name: String) =
            VaultCodec.read(
                javaClass.getResourceAsStream("/vault/$name")!!.use { it.readBytes() },
                credentials("password"),
            )
        val local = read("absent-local.kdbx")
        val remote = read("absent-remote.kdbx")
        val forward = VaultMerge.merge(local, remote)
        val reverse = VaultMerge.merge(remote, local)
        val rootChild = UUID.fromString("00000000-0000-0000-0000-000000000001")
        assertEquals(rootChild, forward.content.group.groups.single().uuid)
        assertEquals(rootChild, reverse.content.group.groups.single().uuid)
        assertEquals(forward.content.group, VaultMerge.merge(forward, remote).content.group)
        assertEquals(
            Instant.ofEpochSecond(10),
            forward.content.group.groups.single().times?.locationChanged,
        )
        assertEquals(
            Instant.ofEpochSecond(20),
            forward.content.group.groups.single().groups.single().times?.locationChanged,
        )
    }

    @Test
    fun absentGroupTimesMustNotChangeCycleResolutionWithMergeDirection() {
        val base = VaultCodec.create("password")
        val a = Group(UUID.fromString("00000000-0000-0000-0000-000000000001"), "A", times = null)
        val b = Group(UUID.fromString("00000000-0000-0000-0000-000000000002"), "B", times = null)
        val movedA =
            a.copy(
                times =
                    TimeData(
                        creationTime = null,
                        lastAccessTime = null,
                        lastModificationTime = null,
                        expiryTime = null,
                        locationChanged = Instant.ofEpochSecond(10),
                    )
            )
        val movedB =
            b.copy(
                times =
                    TimeData(
                        creationTime = null,
                        lastAccessTime = null,
                        lastModificationTime = null,
                        expiryTime = null,
                        locationChanged = Instant.ofEpochSecond(20),
                    )
            )
        val local =
            base.withContent(
                base.content.copy(
                    group =
                        base.content.group.copy(groups = listOf(a.copy(groups = listOf(movedB))))
                )
            )
        val remote =
            base.withContent(
                base.content.copy(
                    group =
                        base.content.group.copy(groups = listOf(b.copy(groups = listOf(movedA))))
                )
            )
        System.getProperty("review.fixture.dir")?.let { directory ->
            java.io.File(directory, "absent-local.kdbx").writeBytes(local.bytes())
            java.io.File(directory, "absent-remote.kdbx").writeBytes(remote.bytes())
        }
        val diskLocal = VaultCodec.read(local.bytes(), local.credentials)
        val diskRemote = VaultCodec.read(remote.bytes(), remote.credentials)
        val forward = VaultMerge.merge(diskLocal, diskRemote)
        val reverse = VaultMerge.merge(diskRemote, diskLocal)
        println(
            "forward root child=${forward.content.group.groups.single().name}; reverse root child=${reverse.content.group.groups.single().name}"
        )
        assertEquals(a.uuid, forward.content.group.groups.single().uuid)
        assertEquals(a.uuid, reverse.content.group.groups.single().uuid)
        assertEquals(
            Instant.ofEpochSecond(10),
            forward.content.group.groups.single().times?.locationChanged,
        )
        assertEquals(
            Instant.ofEpochSecond(20),
            forward.content.group.groups.single().groups.single().times?.locationChanged,
        )
        val repeated = VaultMerge.merge(forward, diskRemote)
        assertEquals(forward.content.group, repeated.content.group)
        assertEquals(
            "The newest edge must survive in both merge directions",
            forward.content.group.groups.single().uuid,
            reverse.content.group.groups.single().uuid,
        )
    }
}
