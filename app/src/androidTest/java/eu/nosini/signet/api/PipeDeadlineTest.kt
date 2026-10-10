// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.api

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.InterruptedIOException
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PipeDeadlineTest {
    @Test
    fun stoppedWriterCannotHoldARequest() {
        val pair = ParcelFileDescriptor.createReliablePipe()
        try {
            val start = SystemClock.elapsedRealtime()
            val input = DeadlineFd(pair[0], start + 100).input()
            try {
                input.read()
                fail("Expected deadline")
            } catch (_: InterruptedIOException) {}
            assertTrue(SystemClock.elapsedRealtime() - start < 3000)
        } finally {
            pair.forEach { it.close() }
        }
    }

    @Test
    fun stoppedReaderCannotHoldARequest() {
        val pair = ParcelFileDescriptor.createReliablePipe()
        try {
            val start = SystemClock.elapsedRealtime()
            val output = DeadlineFd(pair[1], start + 100).output()
            try {
                output.write(ByteArray(1024 * 1024))
                fail("Expected deadline")
            } catch (_: InterruptedIOException) {}
            assertTrue(SystemClock.elapsedRealtime() - start < 3000)
        } finally {
            pair.forEach { it.close() }
        }
    }
}
