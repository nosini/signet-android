// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.app.Application
import android.content.Intent
import eu.nosini.signet.api.*
import eu.nosini.signet.vault.*
import java.util.concurrent.*
import mockwebserver3.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class RepositoryConcurrencyTest {
    @Test
    fun slowSyncDoesNotBlockUiReadsOrLockAndCannotUnlockAgain() {
        MockWebServer().use { server ->
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            server.dispatcher =
                object : Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse {
                        if (request.method == "GET") {
                            started.countDown()
                            check(release.await(5, TimeUnit.SECONDS))
                            return MockResponse.Builder().code(404).build()
                        }
                        return MockResponse.Builder().code(204).build()
                    }
                }
            server.start()
            val repo =
                Repository(RuntimeEnvironment.getApplication()) {
                    DavConfig(server.url("/vault.kdbx").toString())
                }
            repo.create("password")
            val executor = Executors.newFixedThreadPool(2)
            val syncing = executor.submit<Unit> { repo.sync() }
            try {
                assertTrue(started.await(5, TimeUnit.SECONDS))
                executor
                    .submit<Unit> {
                        assertTrue(repo.unlocked)
                        repo.keys()
                        repo.touch()
                        repo.lock()
                        assertFalse(repo.unlocked)
                    }
                    .get(200, TimeUnit.MILLISECONDS)
            } finally {
                release.countDown()
                syncing.get(5, TimeUnit.SECONDS)
                executor.shutdownNow()
                repo.lock()
            }
            assertFalse(repo.unlocked)
        }
    }

    @Test
    fun oneCallerCannotFillTheGlobalPendingFlowTable() {
        val caller = Caller(1000, listOf(CallerApp("one.app", setOf("cert"), "One")))
        val other = Caller(1001, listOf(CallerApp("two.app", setOf("cert"), "Two")))
        val ids = mutableListOf<String>()
        try {
            repeat(8) { ids += PendingFlows.add("register", caller, Intent(), 0) }
            assertTrue(runCatching { PendingFlows.add("register", caller, Intent(), 0) }.isFailure)
            ids += PendingFlows.add("register", other, Intent(), 0)
        } finally {
            ids.forEach(PendingFlows::take)
        }
    }
}
