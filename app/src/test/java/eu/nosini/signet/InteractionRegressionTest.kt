// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.Intent
import androidx.lifecycle.ViewModelProvider
import eu.nosini.signet.api.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = SignetApplication::class)
class InteractionRegressionTest {
    @Test
    fun consumedFlowSurvivesRecreationAndObscuredTouchesAreFiltered() {
        val caller = Caller(1000, listOf(CallerApp("test.app", setOf("cert"), "Test")))
        val id = PendingFlows.add("register", caller, Intent(), 0)
        val intent = Intent().putExtra("flow", id)
        val controller = Robolectric.buildActivity(InteractionActivity::class.java, intent).setup()
        try {
            val before = controller.get()
            val flow = ViewModelProvider(before)[InteractionActivity.FlowState::class.java].flow
            assertNotNull(flow)
            assertTrue(before.window.decorView.filterTouchesWhenObscured)
            assertNull(PendingFlows.take(id))
            controller.recreate()
            val after = controller.get()
            assertFalse(after.isFinishing)
            assertSame(
                flow,
                ViewModelProvider(after)[InteractionActivity.FlowState::class.java].flow,
            )
            assertTrue(after.window.decorView.filterTouchesWhenObscured)
        } finally {
            controller.pause().stop().destroy()
        }
    }
}
