// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.app.Application
import android.content.*
import android.os.Build
import app.keemobile.kotpass.database.*
import eu.nosini.signet.api.*
import eu.nosini.signet.crypto.Crypto
import eu.nosini.signet.vault.*
import java.io.File
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import org.bouncycastle.openpgp.*
import org.json.*

class SignetApplication : Application() {
    lateinit var repository: Repository
        private set

    override fun onCreate() {
        super.onCreate()
        repository = Repository(this)
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (repository.preferences.getBoolean("lock-screen", true)) repository.lock()
                }
            }
        if (Build.VERSION.SDK_INT >= 33)
            registerReceiver(
                receiver,
                IntentFilter(Intent.ACTION_SCREEN_OFF),
                Context.RECEIVER_NOT_EXPORTED,
            )
        else
            @Suppress("DEPRECATION")
            registerReceiver(receiver, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }
}

data class IndexedKey(
    val armor: String,
    val own: Boolean,
    val entry: String? = null,
    val peerAddress: String? = null,
    val peerIdentity: String? = null,
) {
    val certificate: PGPPublicKeyRing
        get() = Crypto.publicKey(armor)

    val id: Long
        get() = certificate.publicKey.keyID

    val fingerprint: String
        get() = Crypto.fingerprint(certificate)

    val userId: String
        get() = info.primaryUserId ?: fingerprint

    val info
        get() = Crypto.pgp.inspect(Crypto.pgp.toCertificate(certificate))
}

class Repository(val context: Context) {
    val preferences = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val secure = SecureStore(context)
    val registrations: Registrations = AppRegistrations(context)
    val approvals = Approvals()
    val updates = MutableStateFlow(0)
    val file = File(context.filesDir, "vault.kdbx")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var lastUse = android.os.SystemClock.elapsedRealtime()
    private var lastSync = 0L
    private var db: KeePassDatabase? = null
    private val unlockedKeys = mutableMapOf<String, PGPSecretKeyRing>()
    private var index = loadIndex("public-index.json")
    private var peers = loadIndex("autocrypt-index.json")
    var error: String? = null
        private set

    val unlocked: Boolean
        @Synchronized get() = db != null

    init {
        scope.launch {
            while (isActive) {
                delay(10_000)
                tick()
            }
        }
    }

    private fun loadIndex(name: String): List<IndexedKey> = runCatching {
        val array = JSONArray(File(context.filesDir, name).readText())
        (0 until array.length()).map {
            val item = array.getJSONObject(it)
            IndexedKey(
                item.getString("armor"),
                item.optBoolean("own"),
                item.optString("entry").ifBlank { null },
                item.optString("peerAddress").ifBlank { null },
                item.optString("peerIdentity").ifBlank { null },
            )
        }
    }
        .getOrDefault(emptyList())

    private fun writeIndex(name: String, keys: List<IndexedKey>) {
        val array = JSONArray()
        keys.forEach {
            array.put(
                JSONObject()
                    .put("armor", it.armor)
                    .put("own", it.own)
                    .put("entry", it.entry ?: "")
                    .put("peerAddress", it.peerAddress ?: "")
                    .put("peerIdentity", it.peerIdentity ?: "")
            )
        }
        atomicWrite(File(context.filesDir, name), array.toString().toByteArray())
    }

    @Synchronized fun keys(): List<IndexedKey> = index

    @Synchronized fun peers(caller: Caller): List<IndexedKey> = peers.filter {
        it.peerIdentity == caller.identity
    }

    @Synchronized
    fun secret(id: Long): PGPSecretKeyRing? {
        touch()
        return db?.keyEntries()?.firstNotNullOfOrNull { entry ->
            entry.fields[PRIVATE_KEY]?.content?.let { armor ->
                runCatching {
                    unlockedKeys[WebDav.hash(armor.toByteArray())]
                        ?: Crypto.secretKey(armor).let { ring ->
                            if (Crypto.protected(ring))
                                entry.fields["Password"]
                                    ?.content
                                    ?.takeIf { it.isNotEmpty() }
                                    ?.let { pass ->
                                        runCatching { Crypto.unprotect(ring, pass) }.getOrNull()
                                    } ?: ring
                            else ring
                        }
                }
                    .getOrNull()
                    ?.takeIf {
                        it.publicKey.keyID == id ||
                            it.publicKeys.asSequence().any { sub -> sub.keyID == id }
                    }
            }
        }
    }

    @Synchronized
    fun touch() {
        lastUse = android.os.SystemClock.elapsedRealtime()
    }

    @Synchronized
    fun lock() {
        db = null
        unlockedKeys.clear()
        approvals.clear()
        changed()
    }

    @Synchronized
    fun unlock(password: String) {
        val key = File(context.filesDir, "keyfile").takeIf { it.exists() }?.readBytes()
        try {
            db = VaultCodec.read(file.readBytes(), credentials(password, key))
            refresh()
            touch()
            error = null
        } finally {
            key?.fill(0)
        }
        scope.launch { runCatching { sync() }.onFailure { setError(it) } }
    }

    @Synchronized
    fun create(password: String) {
        check(!file.exists()) { "Vault already exists" }
        val keyFile = File(context.filesDir, "keyfile").takeIf { it.exists() }?.readBytes()
        try {
            db = VaultCodec.create(password, keyFile)
            save()
        } finally {
            keyFile?.fill(0)
        }
    }

    @Synchronized
    fun open(bytes: ByteArray) {
        check(!file.exists()) { "A vault already exists" }
        atomicWrite(file, bytes)
        lock()
    }

    @Synchronized
    fun importKey(text: String, passphrase: String = "") {
        val database = db ?: error("Unlock the vault first")
        val secret = runCatching {
            Crypto.secretKey(text)
        }
            .getOrNull()
            ?.let { if (Crypto.protected(it)) Crypto.unprotect(it, passphrase) else it }
        val public = secret?.let(Crypto::publicPart) ?: Crypto.publicKey(text)
        val fingerprint = Crypto.fingerprint(public)
        val previous = database.keyEntries().find { it.fields[FINGERPRINT]?.content == fingerprint }
        // Joining certificate packets retains certifications and existing secret packets.
        val joinedPublic =
            previous?.fields?.get(PUBLIC_KEY)?.content?.let {
                PGPPublicKeyRing.join(Crypto.publicKey(it), public)
            } ?: public
        val joinedSecret =
            if (secret != null) {
                previous?.fields?.get(PRIVATE_KEY)?.content?.let { old ->
                    val oldRing = Crypto.secretKey(old)
                    var combined = oldRing
                    secret.secretKeys.asSequence().forEach { newKey ->
                        if (
                            combined.getSecretKey(newKey.keyID) == null || !newKey.isPrivateKeyEmpty
                        )
                            combined = PGPSecretKeyRing.insertSecretKey(combined, newKey)
                    }
                    PGPSecretKeyRing.replacePublicKeys(combined, joinedPublic)
                } ?: PGPSecretKeyRing.replacePublicKeys(secret, joinedPublic)
            } else
                previous?.fields?.get(PRIVATE_KEY)?.content?.let {
                    PGPSecretKeyRing.replacePublicKeys(Crypto.secretKey(it), joinedPublic)
                }
        db =
            VaultCodec.put(
                database,
                fingerprint,
                Crypto.armor(joinedPublic),
                joinedSecret?.let(Crypto::armor),
                joinedPublic.publicKey.userIDs.asSequence().firstOrNull() ?: fingerprint,
            )
        saveAndSync()
    }

    @Synchronized
    fun delete(entry: String) {
        db = VaultCodec.delete(db ?: error("Unlock first"), java.util.UUID.fromString(entry))
        saveAndSync()
    }

    @Synchronized
    private fun save() {
        atomicWrite(file, db!!.bytes())
        refresh()
        touch()
    }

    private fun saveAndSync() {
        save()
        scope.launch { runCatching { sync() }.onFailure { setError(it) } }
    }

    @Synchronized
    private fun refresh() {
        index =
            db!!.keyEntries().mapNotNull { entry ->
                runCatching {
                    val secret = entry.fields[PRIVATE_KEY]?.content?.takeIf { it.isNotBlank() }
                    val public =
                        secret?.let { Crypto.publicPart(Crypto.secretKey(it)) }
                            ?: Crypto.publicKey(entry.fields[PUBLIC_KEY]!!.content)
                    IndexedKey(Crypto.armor(public), secret != null, entry.uuid.toString())
                }
                    .getOrNull()
            }
        writeIndex("public-index.json", index)
        changed()
    }

    @Synchronized
    fun updatePeer(caller: Caller, rawAddress: String, bytes: ByteArray, rawDate: Long) {
        val address = OpenPgpRequestHandler.email(rawAddress)
        val date = minOf(rawDate, System.currentTimeMillis())
        val stateKey = "peer:${caller.identity}:$address"
        require(bytes.size <= 1024 * 1024) { "Autocrypt key exceeds 1 MiB" }
        val last = preferences.getLong(stateKey, 0)
        if (date < last) return
        val public = Crypto.publicKey(bytes)
        require(
            Crypto.pgp.inspect(Crypto.pgp.toCertificate(public)).validUserIds.any {
                OpenPgpRequestHandler.email(it) == OpenPgpRequestHandler.email(address)
            }
        ) {
            "Autocrypt key does not match the peer address"
        }
        val key = IndexedKey(Crypto.armor(public), false, stateKey, address, caller.identity)
        peers = peers.filter { it.entry != key.entry } + key
        writeIndex("autocrypt-index.json", peers)
        preferences.edit().putLong(stateKey, date).apply()
        changed()
    }

    @Synchronized
    fun unlockProtected(id: Long, password: String) {
        val database = db ?: error("Unlock the vault first")
        val candidates =
            database
                .keyEntries()
                .mapNotNull { it.fields[PRIVATE_KEY]?.content }
                .map { it to Crypto.secretKey(it) }
                .filter { (_, ring) ->
                    id == 0L ||
                        ring.publicKey.keyID == id ||
                        ring.publicKeys.asSequence().any { it.keyID == id }
                }
        for ((armor, ring) in candidates) if (Crypto.protected(ring)) {
            unlockedKeys[WebDav.hash(armor.toByteArray())] = Crypto.unprotect(ring, password)
        }
    }

    @Synchronized
    fun checkPassword(password: String) {
        val key = File(context.filesDir, "keyfile").takeIf { it.exists() }?.readBytes()
        try {
            VaultCodec.read(file.readBytes(), credentials(password, key))
        } finally {
            key?.fill(0)
        }
    }

    @Synchronized
    fun reauthenticatedExport(password: String, id: Long): String {
        checkPassword(password)
        return secret(id)?.let(Crypto::armor) ?: error("Secret key unavailable")
    }

    fun dav(): DavConfig? {
        val url = preferences.getString("dav-url", "")!!
        if (url.isBlank()) return null
        val password = secure.read("webdav")
        try {
            return DavConfig(url, preferences.getString("dav-user", "")!!, String(password))
        } finally {
            password.fill(0)
        }
    }

    fun configureDav(url: String, username: String, password: String) {
        DavConfig(url, username, password)
        val bytes = password.toByteArray()
        try {
            secure.save("webdav", bytes)
        } finally {
            bytes.fill(0)
        }
        preferences
            .edit()
            .putString("dav-url", url)
            .putString("dav-user", username)
            .remove("sync-state")
            .apply()
    }

    @Synchronized
    fun sync() {
        val config = dav() ?: return
        val database = db ?: error("Unlock the vault to sync")
        val json = JSONObject(preferences.getString("sync-state", "{}")!!)
        val state =
            SyncState(
                json.optString("endpoint"),
                json.optString("etag").ifEmpty { null },
                json.optString("localHash"),
                json.optString("remoteHash"),
            )
        val result = WebDav().sync(file, database, config, state)
        db = result.database
        val s = result.state
        preferences
            .edit()
            .putString(
                "sync-state",
                JSONObject()
                    .put("endpoint", s.endpoint)
                    .put("etag", s.etag ?: "")
                    .put("localHash", s.localHash)
                    .put("remoteHash", s.remoteHash)
                    .toString(),
            )
            .putLong("last-sync", System.currentTimeMillis())
            .apply()
        lastSync = android.os.SystemClock.elapsedRealtime()
        error = null
        refresh()
    }

    @Synchronized
    private fun tick() {
        val now = android.os.SystemClock.elapsedRealtime()
        if (db != null && now - lastUse >= preferences.getLong("lock-minutes", 5) * 60_000) {
            lock()
            return
        }
        if (db != null && now - lastSync >= preferences.getLong("sync-minutes", 5) * 60_000)
            runCatching { sync() }.onFailure { setError(it) }
    }

    @Synchronized
    fun setError(failure: Throwable) {
        error = failure.message ?: "Operation failed"
        changed()
    }

    private fun changed() {
        updates.value += 1
    }
}
