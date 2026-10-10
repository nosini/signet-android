// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.vault

import app.keemobile.kotpass.cryptography.EncryptedValue
import app.keemobile.kotpass.database.*
import app.keemobile.kotpass.database.modifiers.binaries
import app.keemobile.kotpass.database.modifiers.modifyBinaries
import app.keemobile.kotpass.models.*
import java.io.*
import java.time.Instant
import java.util.UUID

const val PRIVATE_KEY = "gpg_privateKeyArmored"
const val PUBLIC_KEY = "gpg_publicKeyArmored"
const val FINGERPRINT = "gpg_fingerprint"

fun credentials(password: String, keyFile: ByteArray? = null): Credentials =
    if (keyFile == null) Credentials.from(EncryptedValue.fromString(password))
    else if (password.isEmpty()) Credentials.from(keyFile)
    else Credentials.from(EncryptedValue.fromString(password), keyFile)

fun KeePassDatabase.withContent(content: DatabaseContent): KeePassDatabase =
    when (this) {
        is KeePassDatabase.Ver4x -> copy(content = content)
        is KeePassDatabase.Ver3x -> copy(content = content)
    }

fun KeePassDatabase.bytes(): ByteArray = ByteArrayOutputStream().also { encode(it) }.toByteArray()

fun atomicWrite(file: File, bytes: ByteArray) {
    file.parentFile!!.mkdirs()
    val tmp = File.createTempFile(".signet-", ".tmp", file.parentFile)
    try {
        FileOutputStream(tmp).use {
            it.write(bytes)
            it.fd.sync()
        }
        check(tmp.renameTo(file)) { "Could not replace ${file.name}" }
    } finally {
        tmp.delete()
    }
}

fun Group.transform(id: UUID, change: (Entry) -> Entry?): Group =
    copy(
        entries = entries.mapNotNull { if (it.uuid == id) change(it) else it },
        groups = groups.map { it.transform(id, change) },
    )

fun Group.entriesOutside(recycle: UUID?): List<Entry> =
    if (uuid == recycle) emptyList() else entries + groups.flatMap { it.entriesOutside(recycle) }

fun KeePassDatabase.keyEntries(): List<Entry> =
    content.group.entriesOutside(content.meta.recycleBinUuid).filter {
        it.fields[PRIVATE_KEY]?.content?.isNotBlank() == true ||
            it.fields[PUBLIC_KEY]?.content?.isNotBlank() == true
    }

object VaultCodec {
    fun create(password: String, keyFile: ByteArray? = null): KeePassDatabase {
        val now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
        val db =
            KeePassDatabase.Ver4x.create(
                "Signet",
                Meta(
                    name = "Signet",
                    settingsChanged = now,
                    nameChanged = now,
                    descriptionChanged = now,
                    defaultUserChanged = now,
                ),
                credentials(password, keyFile),
            )
        val kdf =
            db.header.kdfParameters as app.keemobile.kotpass.database.header.KdfParameters.Argon2
        return db.copy(
            header =
                db.header.copy(
                    kdfParameters =
                        kdf.copy(
                            variant =
                                app.keemobile.kotpass.database.header.KdfParameters.Argon2.Variant
                                    .Argon2id,
                            memory = 64UL * 1024UL * 1024UL,
                            iterations = 3UL,
                        )
                ),
            content = db.content.copy(group = db.content.group.copy(times = TimeData.create(now))),
        )
    }

    fun read(bytes: ByteArray, credentials: Credentials): KeePassDatabase =
        KeePassDatabase.decode(bytes.inputStream(), credentials, contentParser = SafeXml)

    fun put(
        db: KeePassDatabase,
        fingerprint: String,
        publicKey: String,
        privateKey: String?,
        title: String,
        now: Instant = Instant.now(),
    ): KeePassDatabase {
        val old =
            db.keyEntries().find {
                it.fields[FINGERPRINT]?.content?.equals(fingerprint, true) == true
            }
        val fields =
            (old?.fields ?: EntryFields(emptyMap())) +
                mapOf(
                    "Title" to EntryValue.Plain(title),
                    PUBLIC_KEY to EntryValue.Plain(publicKey),
                    FINGERPRINT to EntryValue.Plain(fingerprint.uppercase()),
                ) +
                (privateKey?.let {
                    mapOf(PRIVATE_KEY to EntryValue.Encrypted(EncryptedValue.fromString(it)))
                } ?: emptyMap())
        val entry =
            (old ?: Entry(UUID.randomUUID(), fields = fields)).copy(
                fields = fields,
                times = (old?.times ?: TimeData.create(now)).copy(lastModificationTime = now),
                history = old?.let { it.history + it.copy(history = emptyList()) } ?: emptyList(),
            )
        val root =
            if (old == null) {
                val group = db.content.group.groups.find { it.name == "Signet" }
                if (group == null)
                    db.content.group.copy(
                        groups =
                            db.content.group.groups +
                                Group(
                                    UUID.randomUUID(),
                                    "Signet",
                                    times = TimeData.create(now),
                                    entries = listOf(entry),
                                )
                    )
                else
                    db.content.group.copy(
                        groups =
                            db.content.group.groups.map {
                                if (it.uuid == group.uuid) it.copy(entries = it.entries + entry)
                                else it
                            }
                    )
            } else db.content.group.transform(old.uuid) { entry }
        return db.withContent(db.content.copy(group = root))
    }

    fun delete(db: KeePassDatabase, id: UUID, now: Instant = Instant.now()): KeePassDatabase {
        val entry = db.keyEntries().find { it.uuid == id } ?: return db
        var root = db.content.group.transform(id) { null }
        var meta = db.content.meta
        if (meta.recycleBinEnabled) {
            var recycle = meta.recycleBinUuid?.let { findGroup(root, it) }
            if (recycle == null) {
                recycle = Group.createRecycleBin("Recycle Bin")
                meta = meta.copy(recycleBinUuid = recycle.uuid, recycleBinChanged = now)
                root = root.copy(groups = root.groups + recycle)
            }
            fun add(g: Group): Group =
                if (g.uuid == recycle.uuid)
                    g.copy(
                        entries =
                            g.entries +
                                entry.copy(
                                    times =
                                        (entry.times ?: TimeData.create(now)).copy(
                                            locationChanged = now
                                        )
                                )
                    )
                else g.copy(groups = g.groups.map(::add))
            return db.withContent(db.content.copy(meta = meta, group = add(root)))
        }
        return db.withContent(
            db.content.copy(
                group = root,
                deletedObjects =
                    db.content.deletedObjects.filter { it.id != id } + DeletedObject(id, now),
            )
        )
    }

    private fun findGroup(group: Group, id: UUID): Group? =
        if (group.uuid == id) group else group.groups.firstNotNullOfOrNull { findGroup(it, id) }
}

/** UUID-based merge. Inputs are immutable; attachment references are content hashes. */
object VaultMerge {
    private data class Located<T>(val value: T, val parent: UUID?)

    private fun time(t: Instant?) = t ?: Instant.EPOCH

    // Kotpass EncryptedValue equality compares random memory masks, not plaintext.
    // Compare hashes of semantic contents, retaining the protection flag.
    private fun signature(entry: Entry): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val structure = entry.copy(fields = EntryFields(emptyMap()), history = emptyList())
        digest.update(structure.toString().toByteArray())
        for ((key, value) in entry.fields.toSortedMap()) {
            for (text in listOf(key, value.content)) {
                val bytes = text.toByteArray()
                try {
                    digest.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.size).array())
                    digest.update(bytes)
                } finally {
                    bytes.fill(0)
                }
            }
            digest.update(if (value is EntryValue.Encrypted) 1.toByte() else 0.toByte())
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    fun merge(local: KeePassDatabase, remote: KeePassDatabase): KeePassDatabase {
        require(local.content.group.uuid == remote.content.group.uuid) {
            "The files belong to different vaults"
        }
        val lg = linkedMapOf<UUID, Located<Group>>()
        val rg = linkedMapOf<UUID, Located<Group>>()
        val le = linkedMapOf<UUID, Located<Entry>>()
        val re = linkedMapOf<UUID, Located<Entry>>()
        fun flatten(
            g: Group,
            parent: UUID?,
            groups: MutableMap<UUID, Located<Group>>,
            entries: MutableMap<UUID, Located<Entry>>,
        ) {
            require(groups.put(g.uuid, Located(g, parent)) == null) { "Duplicate group UUID" }
            g.entries.forEach {
                require(entries.put(it.uuid, Located(it, g.uuid)) == null) {
                    "Duplicate entry UUID"
                }
            }
            g.groups.forEach { flatten(it, g.uuid, groups, entries) }
        }
        flatten(local.content.group, null, lg, le)
        flatten(remote.content.group, null, rg, re)
        val deleted =
            (local.content.deletedObjects + remote.content.deletedObjects)
                .groupBy { it.id }
                .mapValues { (_, values) -> values.maxBy { it.deletionTime } }
        val groups = linkedMapOf<UUID, Located<Group>>()
        for (id in lg.keys + rg.keys) {
            val a = lg[id]
            val b = rg[id]
            val winner =
                if (a == null) b!!
                else if (b == null) a
                else if (
                    time(b.value.times?.lastModificationTime) >
                        time(a.value.times?.lastModificationTime)
                )
                    b
                else a
            val move =
                if (
                    a != null &&
                        b != null &&
                        time(b.value.times?.locationChanged) > time(a.value.times?.locationChanged)
                )
                    b
                else a ?: b!!
            val last = time(winner.value.times?.lastModificationTime)
            if (
                id == local.content.group.uuid ||
                    deleted[id]?.deletionTime?.let { it >= last } != true
            )
                groups[id] =
                    Located(
                        winner.value.copy(
                            times =
                                winner.value.times?.copy(
                                    locationChanged = move.value.times?.locationChanged
                                )
                        ),
                        move.parent,
                    )
        }
        val entries = linkedMapOf<UUID, Located<Entry>>()
        for (id in le.keys + re.keys) {
            val a = le[id]
            val b = re[id]
            val winner =
                if (a == null) b!!
                else if (b == null) a
                else if (
                    time(b.value.times?.lastModificationTime) >
                        time(a.value.times?.lastModificationTime)
                )
                    b
                else a
            val move =
                if (
                    a != null &&
                        b != null &&
                        time(b.value.times?.locationChanged) > time(a.value.times?.locationChanged)
                )
                    b
                else a ?: b!!
            val last = time(winner.value.times?.lastModificationTime)
            if (deleted[id]?.deletionTime?.let { it >= last } == true) continue
            val loser = if (winner === a) b else a
            val snapshot =
                winner.value.copy(
                    history = emptyList(),
                    times =
                        winner.value.times?.copy(
                            locationChanged = move.value.times?.locationChanged
                        ),
                )
            val history =
                ((a?.value?.history ?: emptyList()) +
                        (b?.value?.history ?: emptyList()) +
                        listOfNotNull(loser?.value?.copy(history = emptyList())))
                    .map { it.copy(history = emptyList()) }
                    .distinctBy(::signature)
                    .filter { signature(it) != signature(snapshot) }
                    .sortedBy { time(it.times?.lastModificationTime) }
            entries[id] = Located(snapshot.copy(history = history), move.parent)
        }
        val rootId = local.content.group.uuid
        fun build(id: UUID, path: Set<UUID>): Group {
            require(id !in path) { "Group cycle" }
            return groups
                .getValue(id)
                .value
                .copy(
                    entries = entries.values.filter { it.parent == id }.map { it.value },
                    groups =
                        groups.filter { it.value.parent == id }.keys.map { build(it, path + id) },
                )
        }
        // Orphaned children of deleted groups follow their nearest surviving ancestor.
        fun parent(id: UUID?): UUID {
            var current = id
            val seen = mutableSetOf<UUID>()
            while (current != null && current !in groups) {
                require(seen.add(current)) { "Group cycle" }
                current = (lg[current] ?: rg[current])?.parent
            }
            return current ?: rootId
        }
        groups.keys
            .toList()
            .filter { it != rootId }
            .forEach { groups[it] = groups.getValue(it).copy(parent = parent(groups[it]!!.parent)) }
        entries.keys.toList().forEach {
            entries[it] = entries.getValue(it).copy(parent = parent(entries[it]!!.parent))
        }
        val root = build(rootId, emptySet())
        require(countGroups(root) == groups.size) { "Unreachable groups" }
        val newer =
            if (
                time(remote.content.meta.settingsChanged) > time(local.content.meta.settingsChanged)
            )
                remote
            else local
        val icons = local.content.meta.customIcons.toMutableMap()
        remote.content.meta.customIcons.forEach { (id, icon) ->
            if (icons[id] == null || time(icon.lastModified) > time(icons[id]?.lastModified))
                icons[id] = icon
        }
        val custom = local.content.meta.customData.toMutableMap()
        remote.content.meta.customData.forEach { (name, item) ->
            val old = custom[name]
            if (
                old == null ||
                    time(item.lastModified) > time(old.lastModified) ||
                    (item.lastModified == old.lastModified && newer === remote)
            )
                custom[name] = item
        }
        val meta = newer.content.meta.copy(customIcons = icons, customData = custom)
        val content = DatabaseContent(meta, root, deleted.values.toList())
        val target =
            if (local is KeePassDatabase.Ver4x && newer is KeePassDatabase.Ver4x)
                newer.copy(credentials = local.credentials, content = content)
            else local.withContent(content)
        return target.modifyBinaries { local.binaries + remote.binaries }
    }

    private fun countGroups(g: Group): Int = 1 + g.groups.sumOf(::countGroups)
}
