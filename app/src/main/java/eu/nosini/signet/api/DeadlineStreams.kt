// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.api

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.*
import java.io.*

/** Nonblocking descriptors plus poll bound stalled client reads and writes. */
internal class DeadlineFd(
    private val descriptor: ParcelFileDescriptor,
    private val deadline: Long,
) {
    private val fd = descriptor.fileDescriptor

    init {
        val error = NativeIo.setNonblocking(descriptor.fd)
        if (error != 0) throw IOException("Could not configure OpenPGP stream (errno $error)")
    }

    private fun ready(output: Boolean) {
        while (true) {
            val remaining = deadline - SystemClock.elapsedRealtime()
            if (remaining <= 0) throw InterruptedIOException("OpenPGP stream timed out")
            val poll =
                StructPollfd().apply {
                    fd = this@DeadlineFd.fd
                    events = (if (output) OsConstants.POLLOUT else OsConstants.POLLIN).toShort()
                }
            try {
                if (Os.poll(arrayOf(poll), minOf(1000, remaining).toInt()) > 0) {
                    if (poll.revents.toInt() and OsConstants.POLLNVAL != 0)
                        throw IOException("Client closed the stream")
                    return
                }
            } catch (e: ErrnoException) {
                if (e.errno != OsConstants.EINTR) throw IOException("Stream poll failed", e)
            }
        }
    }

    fun input(): InputStream =
        object : InputStream() {
            override fun read(): Int {
                val one = ByteArray(1)
                return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 255
            }

            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                if (length == 0) return 0
                while (true) {
                    ready(false)
                    try {
                        val n = Os.read(fd, bytes, offset, length)
                        return if (n == 0) -1 else n
                    } catch (e: ErrnoException) {
                        if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR)
                            throw IOException("Client input failed", e)
                    }
                }
            }

            override fun close() = descriptor.close()
        }

    fun output(): OutputStream =
        object : OutputStream() {
            override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)

            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                var written = 0
                while (written < length) {
                    ready(true)
                    try {
                        written += Os.write(fd, bytes, offset + written, length - written)
                    } catch (e: ErrnoException) {
                        if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR)
                            throw IOException("Client output failed", e)
                    }
                }
            }

            override fun close() = descriptor.close()
        }
}

internal object NativeIo {
    init {
        System.loadLibrary("signet_io")
    }

    external fun setNonblocking(fd: Int): Int
}
