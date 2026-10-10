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
