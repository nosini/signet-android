// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.api

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.security.SecureRandom

const val APPROVAL_TOKEN = "eu.nosini.signet.approval"

data class CallerApp(val packageName: String, val certificates: Set<String>, val label: String)

data class Caller(val uid: Int, val apps: List<CallerApp>) {
    val identity: String
        get() =
            apps
                .sortedBy { it.packageName }
                .joinToString(";") {
                    it.packageName + ":" + it.certificates.sorted().joinToString(",")
                }

    val label: String
        get() = apps.joinToString(", ") { eu.nosini.signet.displayText(it.label) }

    companion object {
        @Suppress("DEPRECATION")
        fun resolve(context: Context, uid: Int): Caller {
            val pm = context.packageManager
            val packages = pm.getPackagesForUid(uid)?.toList().orEmpty()
            require(packages.isNotEmpty()) { "Caller has no package" }
            val apps = packages.map { name ->
                val info =
                    pm.getPackageInfo(
                        name,
                        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
                        else PackageManager.GET_SIGNATURES,
                    )
                // Pin the current signer set. A changed signer requires the user to register again.
                val signatures =
                    if (Build.VERSION.SDK_INT >= 28) info.signingInfo!!.apkContentsSigners
                    else info.signatures!!
                CallerApp(
                    name,
                    signatures
                        .map { sig ->
                            MessageDigest.getInstance("SHA-256")
                                .digest(sig.toByteArray())
                                .joinToString("") { "%02x".format(it) }
                        }
                        .toSet(),
                    pm.getApplicationLabel(pm.getApplicationInfo(name, 0)).toString(),
                )
            }
            return Caller(uid, apps)
        }
    }
}

interface Registrations {
    fun registered(caller: Caller): Boolean

    fun register(caller: Caller)

    fun revoke(packageName: String)

    fun list(): Map<String, Set<String>>
}

class AppRegistrations(context: Context) : Registrations {
    private val preferences = context.getSharedPreferences("connected-apps", Context.MODE_PRIVATE)

    override fun registered(caller: Caller) =
        caller.apps.isNotEmpty() &&
            caller.apps.all { preferences.getStringSet(it.packageName, null) == it.certificates }

    override fun register(caller: Caller) {
        preferences
            .edit()
            .apply { caller.apps.forEach { putStringSet(it.packageName, it.certificates) } }
            .commit()
    }

    override fun revoke(packageName: String) {
        preferences.edit().remove(packageName).commit()
    }

    override fun list(): Map<String, Set<String>> =
        preferences.all.keys.associateWith { preferences.getStringSet(it, emptySet())!!.toSet() }
}

class Approvals(private val clock: () -> Long = { android.os.SystemClock.elapsedRealtime() }) {
    private data class Grant(
        val identity: String,
        val action: String,
        val key: Long,
        val expires: Long,
    )

    private val grants = mutableMapOf<String, Grant>()
    private val remembered = mutableMapOf<Triple<String, String, Long>, Long>()

    @Synchronized
    fun approve(caller: Caller, action: String, key: Long, rememberMillis: Long = 0): String {
        cleanup()
        val token =
            ByteArray(32)
                .also { SecureRandom().nextBytes(it) }
                .joinToString("") { "%02x".format(it) }
        grants[token] = Grant(caller.identity, action, key, clock() + 120_000)
        if (rememberMillis > 0)
            remembered[Triple(caller.identity, action, key)] =
                if (rememberMillis == Long.MAX_VALUE) Long.MAX_VALUE else clock() + rememberMillis
        return token
    }

    @Synchronized
    fun consume(caller: Caller, action: String, key: Long, token: String?): Boolean {
        cleanup()
        val match = { grant: Grant ->
            grant.identity == caller.identity && grant.action == action && grant.key == key
        }
        if (token != null) {
            val grant = grants.remove(token) ?: return false
            return match(grant)
        }
        val entry = grants.entries.find { match(it.value) }
        if (entry != null) {
            grants.remove(entry.key)
            return true
        }
        return remembered[Triple(caller.identity, action, key)]?.let { it > clock() } == true
    }

    @Synchronized
    fun clear() {
        grants.clear()
        remembered.clear()
    }

    private fun cleanup() {
        grants.entries.removeAll { it.value.expires <= clock() }
        remembered.entries.removeAll { it.value <= clock() }
    }
}
