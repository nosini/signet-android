// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.api

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.*
import eu.nosini.signet.*
import java.io.*
import java.util.UUID
import java.util.concurrent.*
import org.openintents.openpgp.*
import org.openintents.openpgp.util.OpenPgpApi.*

/** PendingIntents contain only opaque IDs. Caller-controlled extras never become approval state. */
object PendingFlows {
    data class Flow(
        val mode: String,
        val caller: Caller,
        val request: Intent,
        val key: Long,
        val expires: Long,
    )

    private val flows = mutableMapOf<String, Flow>()

    @Synchronized
    fun add(mode: String, caller: Caller, request: Intent, key: Long): String {
        flows.entries.removeAll { it.value.expires <= SystemClock.elapsedRealtime() }
        require(flows.size < 128) { "Too many pending requests" }
        val id = UUID.randomUUID().toString()
        flows[id] = Flow(mode, caller, request, key, SystemClock.elapsedRealtime() + 120_000)
        return id
    }

    @Synchronized
    fun take(id: String): Flow? =
        flows.remove(id)?.takeIf { it.expires > SystemClock.elapsedRealtime() }
}

class OpenPgpService : Service() {
    private val pipes = mutableMapOf<Pair<Int, Int>, ParcelFileDescriptor>()
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private val repo
        get() = (application as SignetApplication).repository

    private fun handler() =
        OpenPgpRequestHandler(
            object : KeyBackend {
                override fun keys() = repo.keys()

                override fun secret(id: Long) = repo.secret(id)

                override val unlocked
                    get() = repo.unlocked

                override fun peers(caller: Caller) = repo.peers(caller)

                override fun updatePeer(
                    caller: Caller,
                    address: String,
                    bytes: ByteArray,
                    date: Long,
                ) = repo.updatePeer(caller, address, bytes, date)
            },
            repo.registrations,
            repo.approvals,
        ) { mode, caller, request, key ->
            val id = PendingFlows.add(mode, caller, request, key)
            val intent =
                Intent(this, InteractionActivity::class.java)
                    .setData(android.net.Uri.parse("signet:flow:$id"))
                    .putExtra("flow", id)
            Intent()
                .putExtra(RESULT_CODE, RESULT_CODE_USER_INTERACTION_REQUIRED)
                .putExtra(
                    RESULT_INTENT,
                    PendingIntent.getActivity(
                        this,
                        0,
                        intent,
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_ONE_SHOT,
                    ),
                )
        }

    private val modern =
        object : IOpenPgpService2.Stub() {
            override fun createOutputPipe(pipeId: Int): ParcelFileDescriptor {
                val uid = Binder.getCallingUid()
                Caller.resolve(this@OpenPgpService, uid)
                val key = uid to pipeId
                val pair =
                    synchronized(pipes) {
                        require(
                            key in pipes ||
                                (pipes.keys.count { it.first == uid } < 8 && pipes.size < 64)
                        ) {
                            "Too many pipes"
                        }
                        ParcelFileDescriptor.createReliablePipe().also { pair ->
                            pipes.remove(key)?.close()
                            pipes[key] = pair[1]
                        }
                    }
                timer.schedule(
                    {
                        synchronized(pipes) {
                            if (pipes[key] === pair[1]) pipes.remove(key)?.close()
                        }
                    },
                    2,
                    TimeUnit.MINUTES,
                )
                return pair[0]
            }

            override fun execute(data: Intent, input: ParcelFileDescriptor?, pipeId: Int): Intent {
                val uid = Binder.getCallingUid()
                val output = synchronized(pipes) { pipes.remove(uid to pipeId) }
                return perform(data, input, output, uid)
            }
        }
    private val legacy =
        object : IOpenPgpService.Stub() {
            override fun execute(
                data: Intent,
                input: ParcelFileDescriptor?,
                output: ParcelFileDescriptor?,
            ): Intent = perform(data, input, output, Binder.getCallingUid())
        }

    private fun perform(
        data: Intent,
        input: ParcelFileDescriptor?,
        output: ParcelFileDescriptor?,
        uid: Int,
    ): Intent {
        val deadline =
            timer.schedule(
                {
                    runCatching { input?.close() }
                    runCatching { output?.close() }
                },
                120,
                TimeUnit.SECONDS,
            )
        return try {
            val caller = Caller.resolve(this, uid)
            val expires = SystemClock.elapsedRealtime() + 120_000
            val incoming = input?.let { DeadlineFd(it, expires).input() }
            val outgoing =
                output?.let { DeadlineFd(it, expires).output() }
                    ?: object : OutputStream() {
                        override fun write(b: Int) {
                            error("Missing output pipe")
                        }
                    }
            incoming.use { outgoing.use { handler().handle(data, incoming, outgoing, caller) } }
        } catch (e: Exception) {
            OpenPgpRequestHandler.failure(e.message ?: "Provider error")
        } finally {
            deadline.cancel(false)
            runCatching { input?.close() }
            runCatching { output?.close() }
        }
    }

    override fun onBind(intent: Intent): IBinder =
        if (intent.action == "org.openintents.openpgp.IOpenPgpService") legacy else modern

    override fun onDestroy() {
        synchronized(pipes) {
            pipes.values.forEach { it.close() }
            pipes.clear()
        }
        timer.shutdownNow()
        super.onDestroy()
    }
}
