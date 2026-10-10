// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.vault

import app.keemobile.kotpass.database.*
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody

class SyncFailure(val kind: Kind, message: String, cause: Throwable? = null) :
    Exception(message, cause) {
    enum class Kind {
        AUTH,
        REMOTE_CREDENTIALS,
        CORRUPT,
        CONFLICT,
        HTTP,
        NETWORK,
    }
}

data class DavConfig(val url: String, val username: String = "", val password: String = "") {
    init {
        val parsed = url.toHttpUrl()
        require(parsed.isHttps || parsed.host in setOf("localhost", "127.0.0.1", "::1")) {
            "WebDAV requires HTTPS"
        }
        require(parsed.username.isEmpty() && parsed.password.isEmpty() && parsed.fragment == null) {
            "Use separate credentials"
        }
    }
}

data class SyncState(
    val endpoint: String = "",
    val etag: String? = null,
    val localHash: String = "",
    val remoteHash: String = "",
)

data class SyncResult(val database: KeePassDatabase, val state: SyncState, val changed: Boolean)

class WebDav(
    private val client: OkHttpClient =
        OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .callTimeout(60, TimeUnit.SECONDS)
            .build()
) {
    companion object {
        fun hash(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                "%02x".format(it)
            }
    }

    private fun request(config: DavConfig) =
        Request.Builder().url(config.url).apply {
            if (config.username.isNotEmpty())
                header("Authorization", okhttp3.Credentials.basic(config.username, config.password))
        }

    private fun execute(request: Request): Response =
        try {
            client.newCall(request).execute()
        } catch (e: java.io.IOException) {
            throw SyncFailure(SyncFailure.Kind.NETWORK, "WebDAV network error", e)
        }

    private fun Response.check() {
        if (code == 401 || code == 403)
            throw SyncFailure(SyncFailure.Kind.AUTH, "WebDAV authentication failed")
        if (!isSuccessful) throw SyncFailure(SyncFailure.Kind.HTTP, "WebDAV returned HTTP $code")
    }

    fun download(config: DavConfig): ByteArray =
        execute(request(config).get().build()).use {
            it.check()
            body(it)
        }

    private fun body(response: Response): ByteArray {
        val stream = response.body.byteStream()
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        stream.use {
            while (true) {
                val n = it.read(buf)
                if (n < 0) break
                require(out.size() + n <= 256 * 1024 * 1024) { "Vault exceeds 256 MiB" }
                out.write(buf, 0, n)
            }
        }
        return out.toByteArray()
    }

    /** Caller serializes local writes. State is committed only after GET/PUT succeeds. */
    fun sync(
        file: File,
        local: KeePassDatabase,
        config: DavConfig,
        previous: SyncState,
    ): SyncResult {
        val identity = config.url + "\n" + config.username
        val state = if (previous.endpoint == identity) previous else SyncState()
        val original = file.readBytes()
        val localHash = hash(original)
        repeat(3) { attempt ->
            val get =
                request(config)
                    .get()
                    .apply { if (attempt == 0) state.etag?.let { header("If-None-Match", it) } }
                    .build()
            var etag: String? = null
            var remoteHash = state.remoteHash
            var missing = false
            val remote =
                execute(get).use { response ->
                    etag = response.header("ETag")
                    when (response.code) {
                        304 -> {
                            require(attempt == 0 && state.etag != null) { "Unexpected HTTP 304" }
                            etag = state.etag
                            null
                        }
                        404 -> {
                            missing = true
                            null
                        }
                        else -> {
                            response.check()
                            val bytes = body(response)
                            remoteHash = hash(bytes)
                            try {
                                VaultCodec.read(bytes, local.credentials)
                            } catch (e: app.keemobile.kotpass.errors.CryptoError.InvalidKey) {
                                throw SyncFailure(
                                    SyncFailure.Kind.REMOTE_CREDENTIALS,
                                    "Remote vault needs different credentials",
                                    e,
                                )
                            } catch (e: Exception) {
                                throw SyncFailure(
                                    SyncFailure.Kind.CORRUPT,
                                    "Remote vault cannot be read",
                                    e,
                                )
                            }
                        }
                    }
                }
            val localChanged = localHash != state.localHash
            val remoteChanged = remote != null && remoteHash != state.remoteHash
            if (!missing && (remoteHash == localHash || (!localChanged && !remoteChanged)))
                return SyncResult(local, SyncState(identity, etag, localHash, remoteHash), false)
            if (!missing && !localChanged && remoteChanged) {
                val replacement = remote!!.bytes()
                replace(file, original, replacement)
                return SyncResult(
                    remote,
                    SyncState(identity, etag, hash(replacement), remoteHash),
                    true,
                )
            }
            val candidate = if (remoteChanged) VaultMerge.merge(local, remote!!) else local
            val bytes = if (candidate === local) original else candidate.bytes()
            val put =
                request(config)
                    .put(bytes.toRequestBody("application/octet-stream".toMediaType()))
                    .apply {
                        if (missing) header("If-None-Match", "*")
                        else etag?.let { header("If-Match", it) }
                    }
                    .build()
            execute(put).use { response ->
                if (response.code == 412) return@repeat
                response.check()
                if (!bytes.contentEquals(original)) replace(file, original, bytes)
                return SyncResult(
                    candidate,
                    SyncState(identity, response.header("ETag"), hash(bytes), hash(bytes)),
                    !bytes.contentEquals(original),
                )
            }
        }
        throw SyncFailure(
            SyncFailure.Kind.CONFLICT,
            "Remote vault changed during three sync attempts",
        )
    }

    private fun replace(file: File, previous: ByteArray, bytes: ByteArray) {
        val backups = File(file.parentFile, "backups").apply { mkdirs() }
        atomicWrite(
            File(
                backups,
                "vault-${System.currentTimeMillis()}-${java.util.UUID.randomUUID()}.kdbx",
            ),
            previous,
        )
        backups
            .listFiles()
            ?.filter { it.name.startsWith("vault-") && it.extension == "kdbx" }
            ?.sortedByDescending { it.lastModified() }
            ?.drop(5)
            ?.forEach { it.delete() }
        atomicWrite(file, bytes)
    }
}
