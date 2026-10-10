// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import app.keemobile.kotpass.database.*
import eu.nosini.signet.vault.*
import java.nio.file.Files
import java.time.Instant
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okio.Buffer
import org.junit.Assert.*
import org.junit.Test

class SyncTest {
    private fun response(code: Int, bytes: ByteArray? = null, etag: String? = null) =
        MockResponse.Builder()
            .code(code)
            .apply {
                bytes?.let { body(Buffer().write(it)) }
                etag?.let { addHeader("ETag", it) }
            }
            .build()

    @Test
    fun initialUploadUnchangedLocalRemoteMergeAndRace() {
        MockWebServer().use { server ->
            server.start()
            val dir = Files.createTempDirectory("signet-sync").toFile()
            try {
                val file = java.io.File(dir, "vault.kdbx")
                val base = VaultCodec.create("password")
                val bytes = base.bytes()
                file.writeBytes(bytes)
                val config = DavConfig(server.url("/vault.kdbx").toString(), "user", "password")
                val dav = WebDav()
                server.enqueue(response(404))
                server.enqueue(response(201, etag = "\"one\""))
                var result = dav.sync(file, base, config, SyncState())
                assertEquals("GET", server.takeRequest().method)
                val put = server.takeRequest()
                assertEquals("PUT", put.method)
                assertEquals("*", put.headers["If-None-Match"])
                server.enqueue(response(304))
                result = dav.sync(file, result.database, config, result.state)
                assertFalse(result.changed)
                assertEquals("\"one\"", server.takeRequest().headers["If-None-Match"])
                val now = Instant.parse("2026-10-10T12:00:00Z")
                val local =
                    VaultCodec.put(result.database, "LOCAL", "public-local", null, "Local", now)
                file.writeBytes(local.bytes())
                server.enqueue(response(304))
                server.enqueue(response(204, etag = "\"two\""))
                result = dav.sync(file, local, config, result.state)
                server.takeRequest()
                assertEquals("\"one\"", server.takeRequest().headers["If-Match"])
                val remote =
                    VaultCodec.put(result.database, "REMOTE", "public-remote", null, "Remote", now)
                server.enqueue(response(200, remote.bytes(), "\"three\""))
                result = dav.sync(file, result.database, config, result.state)
                assertEquals(2, result.database.keyEntries().size)
                server.takeRequest()
                val edited =
                    VaultCodec.put(result.database, "THIRD", "public-third", null, "Third", now)
                file.writeBytes(edited.bytes())
                val newRemote =
                    VaultCodec.put(remote, "FOURTH", "public-fourth", null, "Fourth", now)
                server.enqueue(response(200, newRemote.bytes(), "\"four\""))
                server.enqueue(response(412))
                server.enqueue(response(200, newRemote.bytes(), "\"five\""))
                server.enqueue(response(204, etag = "\"six\""))
                result = dav.sync(file, edited, config, result.state)
                assertEquals(4, result.database.keyEntries().size)
                server.takeRequest()
                server.takeRequest()
                assertNull(server.takeRequest().headers["If-None-Match"])
                assertEquals("\"five\"", server.takeRequest().headers["If-Match"])
                assertTrue(java.io.File(dir, "backups").listFiles()!!.isNotEmpty())
                // No ETag: compare hashes; avoid writing an identical vault.
                server.enqueue(response(200, file.readBytes()))
                val same = dav.sync(file, result.database, config, result.state.copy(etag = null))
                assertFalse(same.changed)
            } finally {
                dir.deleteRecursively()
            }
        }
    }

    @Test
    fun errorsDoNotReplaceLocalFile() {
        MockWebServer().use { server ->
            server.start()
            val dir = Files.createTempDirectory("signet-sync-errors").toFile()
            try {
                val file = java.io.File(dir, "vault.kdbx")
                val db = VaultCodec.create("password")
                val original = db.bytes()
                file.writeBytes(original)
                val config = DavConfig(server.url("/vault.kdbx").toString())
                val dav = WebDav()
                for ((code, bytes, kind) in
                    listOf(
                        Triple(401, null, SyncFailure.Kind.AUTH),
                        Triple(500, null, SyncFailure.Kind.HTTP),
                        Triple(200, "invalid".toByteArray(), SyncFailure.Kind.CORRUPT),
                        Triple(
                            200,
                            VaultCodec.create("different").bytes(),
                            SyncFailure.Kind.REMOTE_CREDENTIALS,
                        ),
                    )) {
                    server.enqueue(response(code, bytes))
                    try {
                        dav.sync(file, db, config, SyncState())
                        fail()
                    } catch (e: SyncFailure) {
                        assertEquals(kind, e.kind)
                    }
                    assertArrayEquals(original, file.readBytes())
                }
                repeat(3) {
                    server.enqueue(response(404))
                    server.enqueue(response(412))
                }
                try {
                    dav.sync(file, db, config, SyncState())
                    fail()
                } catch (e: SyncFailure) {
                    assertEquals(SyncFailure.Kind.CONFLICT, e.kind)
                }
                assertArrayEquals(original, file.readBytes())
            } finally {
                dir.deleteRecursively()
            }
        }
    }

    @Test
    fun urlPolicy() {
        for (url in
            listOf(
                "http://example.com/vault",
                "https://user:password@example.com/vault",
                "https://example.com/vault#fragment",
            )) {
            try {
                DavConfig(url)
                fail()
            } catch (_: IllegalArgumentException) {}
        }
    }
}
