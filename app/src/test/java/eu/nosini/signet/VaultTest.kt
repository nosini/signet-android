// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.*
import app.keemobile.kotpass.database.modifiers.*
import app.keemobile.kotpass.models.*
import eu.nosini.signet.vault.*
import java.time.Instant
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class VaultTest {
    private fun comparable(content: DatabaseContent): DatabaseContent {
        fun entry(e: Entry): Entry =
            e.copy(
                fields =
                    e.fields.mapValues { (_, value) ->
                        EntryValue.Plain(
                            (if (value is EntryValue.Encrypted) "protected:" else "plain:") +
                                value.content
                        )
                    },
                history = e.history.map(::entry),
            )
        fun group(g: Group): Group =
            g.copy(entries = g.entries.map(::entry), groups = g.groups.map(::group))
        return content.copy(group = group(content.group))
    }

    private val now = Instant.parse("2026-10-10T12:00:00Z")

    @Test
    fun codecHistoryAndDelete() {
        val db = VaultCodec.create("password")
        val first = VaultCodec.put(db, "ABC", "public", "private", "Key", now)
        val entry = first.keyEntries().single()
        assertTrue(entry.fields[PRIVATE_KEY] is EntryValue.Encrypted)
        val next = VaultCodec.put(first, "ABC", "updated", null, "Updated", now.plusSeconds(1))
        assertEquals(entry.uuid, next.keyEntries().single().uuid)
        assertEquals("private", next.keyEntries().single().fields[PRIVATE_KEY]!!.content)
        assertEquals(1, next.keyEntries().single().history.size)
        val roundtrip = VaultCodec.read(next.bytes(), credentials("password"))
        assertEquals(comparable(next.content), comparable(roundtrip.content))
        val deleted = VaultCodec.delete(roundtrip, entry.uuid, now.plusSeconds(2))
        assertTrue(deleted.keyEntries().isEmpty())
        assertEquals(entry.uuid, deleted.content.deletedObjects.single().id)
        val recycle =
            next.withContent(
                next.content.copy(meta = next.content.meta.copy(recycleBinEnabled = true))
            )
        val recycled = VaultCodec.delete(recycle, entry.uuid, now.plusSeconds(2))
        assertTrue(recycled.keyEntries().isEmpty())
        assertTrue(recycled.content.deletedObjects.isEmpty())
        assertNotNull(recycled.content.meta.recycleBinUuid)
    }

    @Test
    fun unrelatedDataRoundtrip() {
        val binary = BinaryData.Uncompressed(true, "attachment".toByteArray())
        val iconId = UUID.randomUUID()
        val entryId = UUID.randomUUID()
        val entry =
            Entry(
                entryId,
                times = TimeData.create(now),
                fields =
                    EntryFields(
                        mapOf(
                            "Title" to EntryValue.Plain("unrelated"),
                            "Extra" to EntryValue.Encrypted(EncryptedValue.fromString("secret")),
                        )
                    ),
                tags = listOf("tag"),
                binaries = listOf(BinaryReference(binary.hash, "attachment.txt")),
                history =
                    listOf(
                        Entry(
                            entryId,
                            times = TimeData.create(now),
                            fields = EntryFields(mapOf("Title" to EntryValue.Plain("history"))),
                        )
                    ),
            )
        val db =
            VaultCodec.create("password")
                .let {
                    it.withContent(
                        it.content.copy(
                            group =
                                it.content.group.copy(
                                    groups =
                                        listOf(
                                            Group(
                                                UUID.randomUUID(),
                                                "Other",
                                                times = TimeData.create(now),
                                                notes = "keep",
                                                entries = listOf(entry),
                                            )
                                        )
                                ),
                            meta =
                                it.content.meta.copy(
                                    customData = mapOf("plugin" to CustomDataValue("keep", now)),
                                    customIcons =
                                        mapOf(
                                            iconId to CustomIcon("icon".toByteArray(), "Icon", now)
                                        ),
                                ),
                            deletedObjects = listOf(DeletedObject(UUID.randomUUID(), now)),
                        )
                    )
                }
                .modifyBinaries { mapOf(binary.hash to binary) }
        System.getenv("SIGNET_FIXTURE_DIR")?.let {
            java.io.File(it, "kotpass.kdbx").writeBytes(db.bytes())
        }
        val decoded = VaultCodec.read(db.bytes(), credentials("password"))
        assertEquals(comparable(db.content), comparable(decoded.content))
        assertEquals(db.binaries.keys, decoded.binaries.keys)
        assertArrayEquals(
            db.binaries.values.single().getContent(),
            decoded.binaries.values.single().getContent(),
        )
    }

    @Test
    fun unmodeledXmlIsRejected() {
        val db = VaultCodec.create("password")
        val xml =
            db.encodeAsXml()
                .replace(
                    "<Meta>",
                    "<Meta><MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce>",
                )
        try {
            SafeXml.unmarshalContent(xml.toByteArray()) { error("Must reject before decrypting") }
            fail()
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("MasterKeyChangeForceOnce"))
        }
    }

    @Test
    fun protectedHistoryDedupesAcrossRead() {
        val first =
            VaultCodec.put(VaultCodec.create("password"), "ABC", "public", "secret", "Key", now)
        val edited = VaultCodec.put(first, "ABC", "new", "secret", "Key", now.plusSeconds(1))
        val read = VaultCodec.read(edited.bytes(), credentials("password"))
        assertEquals(1, VaultMerge.merge(edited, read).keyEntries().single().history.size)
    }

    @Test
    fun newerChildSurvivesDeletedGroup() {
        val db = VaultCodec.create("password")
        val child = Entry(UUID.randomUUID(), times = TimeData.create(now.plusSeconds(2)))
        val parent =
            Group(
                UUID.randomUUID(),
                "Parent",
                times = TimeData.create(now),
                entries = listOf(child),
            )
        val local =
            db.withContent(db.content.copy(group = db.content.group.copy(groups = listOf(parent))))
        val remote =
            db.withContent(
                db.content.copy(
                    deletedObjects =
                        listOf(
                            DeletedObject(parent.uuid, now.plusSeconds(1)),
                            DeletedObject(child.uuid, now.plusSeconds(1)),
                        )
                )
            )
        val merged = VaultMerge.merge(local, remote)
        assertTrue(merged.content.group.groups.isEmpty())
        assertEquals(child.uuid, merged.content.group.entries.single().uuid)
    }

    @Test
    fun mergeAddEditMoveHistoryAndDelete() {
        val base =
            VaultCodec.put(VaultCodec.create("password"), "ABC", "original", null, "Original", now)
        val id = base.keyEntries().single().uuid
        val local = VaultCodec.put(base, "ABC", "local", null, "Local", now.plusSeconds(1))
        val remote = VaultCodec.put(base, "ABC", "remote", null, "Remote", now.plusSeconds(2))
        val merged = VaultMerge.merge(local, remote)
        assertEquals("remote", merged.keyEntries().single().fields[PUBLIC_KEY]!!.content)
        assertEquals(2, merged.keyEntries().single().history.size)
        assertEquals(merged.content, VaultMerge.merge(merged, remote).content)
        val removed = VaultCodec.delete(base, id, now.plusSeconds(1))
        assertEquals(1, VaultMerge.merge(removed, remote).keyEntries().size)
        assertEquals(1, VaultMerge.merge(remote, removed).keyEntries().size)
        val deletedLater = VaultCodec.delete(base, id, now.plusSeconds(3))
        assertTrue(VaultMerge.merge(remote, deletedLater).keyEntries().isEmpty())
        val newGroup =
            Group(
                UUID.randomUUID(),
                "Moved",
                entries =
                    listOf(
                        base
                            .keyEntries()
                            .single()
                            .copy(
                                times =
                                    TimeData.create(now).copy(locationChanged = now.plusSeconds(4))
                            )
                    ),
            )
        val moved =
            base.withContent(
                base.content.copy(
                    group =
                        base.content.group
                            .transform(id) { null }
                            .copy(
                                groups =
                                    base.content.group.groups.map {
                                        it.copy(entries = emptyList())
                                    } + newGroup
                            )
                )
            )
        val moveMerge = VaultMerge.merge(remote, moved)
        assertEquals(
            "remote",
            moveMerge.content.group.groups
                .first { it.uuid == newGroup.uuid }
                .entries
                .single()
                .fields[PUBLIC_KEY]!!
                .content,
        )
        val other = VaultCodec.put(base, "DEF", "other", null, "Other", now.plusSeconds(1))
        assertEquals(2, VaultMerge.merge(local, other).keyEntries().size)
    }
}

class SharedVaultTest {
    @org.junit.Test
    fun malformedHistoryIsRejected() {
        val bytes =
            javaClass.getResourceAsStream("/vault/invalid-history.kdbx")!!.use { it.readBytes() }
        try {
            VaultCodec.read(bytes, credentials("password"))
            org.junit.Assert.fail()
        } catch (e: IllegalArgumentException) {
            org.junit.Assert.assertTrue(e.message!!.contains("History UUID"))
        }
    }

    @org.junit.Test
    fun readAndWriteLinuxFixture() {
        val bytes = javaClass.getResourceAsStream("/vault/keepass.kdbx")!!.use { it.readBytes() }
        val db = VaultCodec.read(bytes, credentials("password"))
        val group = db.content.group.groups.first { it.name == "Other passwords" }
        val entry = group.entries.single()
        org.junit.Assert.assertEquals("secret", entry.fields["Password"]!!.content)
        org.junit.Assert.assertTrue(entry.fields["Password"] is EntryValue.Encrypted)
        org.junit.Assert.assertEquals("edited value", entry.fields["custom field"]!!.content)
        org.junit.Assert.assertEquals(
            "custom value",
            entry.history.single().fields["custom field"]!!.content,
        )
        org.junit.Assert.assertArrayEquals(
            byteArrayOf(1, 2, 3, 4),
            db.binaries.getValue(entry.binaries.single().hash).getContent(),
        )
        org.junit.Assert.assertEquals(
            "custom icon",
            db.content.meta.customIcons.values.single().name,
        )
        org.junit.Assert.assertEquals(
            "plugin value",
            entry.customData.getValue("entry plugin").value,
        )
        org.junit.Assert.assertEquals(1, db.content.deletedObjects.size)
        val read = VaultCodec.read(db.bytes(), credentials("password"))
        org.junit.Assert.assertEquals(
            "secret",
            read.content.group.groups
                .first { it.name == "Other passwords" }
                .entries
                .single()
                .fields["Password"]!!
                .content,
        )
    }
}
