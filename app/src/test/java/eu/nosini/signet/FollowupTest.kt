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

}
