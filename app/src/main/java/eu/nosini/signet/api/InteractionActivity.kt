// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet.api

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.fragment.app.FragmentActivity
import eu.nosini.signet.*
import kotlinx.coroutines.*
import org.openintents.openpgp.util.OpenPgpApi.*

class InteractionActivity : FragmentActivity() {
    private val repo
        get() = (application as SignetApplication).repository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val flow = intent.getStringExtra("flow")?.let { PendingFlows.take(it) }
        if (flow == null) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }
        setContent {
            MaterialTheme {
                var password by remember { mutableStateOf("") }
                var keyPassword by remember { mutableStateOf("") }
                var error by remember { mutableStateOf<String?>(null) }
                var rememberPolicy by remember {
                    mutableIntStateOf(
                        flow.caller.apps.minOf {
                            repo.preferences.getInt(
                                "approval-policy:${it.packageName}",
                                repo.preferences.getInt("approval-policy", 0),
                            )
                        }
                    )
                }
                var selected by remember { mutableStateOf(setOf<Long>()) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()
                val updates by repo.updates.collectAsState()
                val keys = remember(updates) { repo.keys() }
                Surface {
                    Column(
                        Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text(
                            when (flow.mode) {
                                "register" -> "Connect app"
                                "approve" -> "Approve OpenPGP operation"
                                "sign-picker" -> "Choose signing key"
                                else -> "Choose recipient keys"
                            },
                            style = MaterialTheme.typography.headlineSmall,
                        )
                        Text(flow.caller.label)
                        flow.caller.apps.forEach { app ->
                            val icon =
                                remember(app.packageName) {
                                    runCatching {
                                        packageManager
                                            .getApplicationIcon(app.packageName)
                                            .toBitmap(48, 48)
                                            .asImageBitmap()
                                    }
                                        .getOrNull()
                                }
                            icon?.let { Image(it, "${app.label} icon", Modifier.size(48.dp)) }
                            Text(app.packageName)
                            Text(
                                "Certificate SHA-256: ${app.certificates.joinToString()}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        if (flow.mode == "register") {
                            val existing = repo.registrations.list()
                            if (
                                flow.caller.apps.any {
                                    existing[it.packageName]?.let { certs ->
                                        certs != it.certificates
                                    } == true
                                }
                            )
                                Text(
                                    "This app's signing certificate has changed. Register it again only if you trust the change."
                                )
                            Text(
                                "This app will be able to read public keys. Signet asks before signing and decrypting."
                            )
                        } else if (flow.mode == "approve") {
                            Text(flow.request.action!!.substringAfterLast('.'))
                            val key = keys.find { it.id == flow.key }
                            if (key != null) {
                                Text(displayText(key.userId))
                                Text(key.fingerprint.chunked(4).joinToString(" "))
                            } else {
                                Text("Decrypt using available secret keys")
                                keys
                                    .filter { it.own }
                                    .forEach {
                                        Text(
                                            "${displayText(it.userId)}\n${it.fingerprint.chunked(4).joinToString(" ")}"
                                        )
                                    }
                            }
                            if (!repo.unlocked) {
                                OutlinedTextField(
                                    password,
                                    { password = it },
                                    label = { Text("Master password") },
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                if (repo.preferences.getBoolean("biometric", false))
                                    TextButton(
                                        onClick = {
                                            biometric(repo, done = {}, failure = { error = it })
                                        }
                                    ) {
                                        Text("Unlock with biometrics")
                                    }
                            }
                            OutlinedTextField(
                                keyPassword,
                                { keyPassword = it },
                                label = { Text("OpenPGP passphrase, for a protected key") },
                                visualTransformation = PasswordVisualTransformation(),
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Text("Approval policy")
                            listOf(
                                    "Ask every time",
                                    "Allow this operation and key for 5 minutes",
                                    "Allow until vault locks",
                                )
                                .forEachIndexed { i, text ->
                                    Row {
                                        RadioButton(
                                            rememberPolicy == i,
                                            onClick = { rememberPolicy = i },
                                        )
                                        Text(text, Modifier.padding(top = 12.dp))
                                    }
                                }
                        } else {
                            keys
                                .filter {
                                    if (flow.mode == "sign-picker")
                                        it.own && it.info.signingSubkeys.isNotEmpty()
                                    else
                                        it.info.isUsableForEncryption(
                                            org.pgpainless.algorithm.EncryptionPurpose.ANY
                                        )
                                }
                                .forEach { key ->
                                    Row {
                                        Checkbox(
                                            key.id in selected,
                                            onCheckedChange = { checked ->
                                                selected =
                                                    if (flow.mode == "sign-picker")
                                                        (if (checked) setOf(key.id) else emptySet())
                                                    else if (checked) selected + key.id
                                                    else selected - key.id
                                            },
                                        )
                                        Column {
                                            Text(displayText(key.userId))
                                            Text(key.fingerprint.takeLast(16))
                                        }
                                    }
                                }
                        }
                        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            OutlinedButton(
                                onClick = {
                                    setResult(Activity.RESULT_CANCELED)
                                    finish()
                                }
                            ) {
                                Text("Deny")
                            }
                            Button(
                                enabled =
                                    !busy &&
                                        (flow.mode in setOf("approve", "register") ||
                                            selected.isNotEmpty()),
                                onClick = {
                                    busy = true
                                    scope.launch {
                                        try {
                                            val result =
                                                withContext(Dispatchers.IO) {
                                                    require(
                                                        flow.expires > SystemClock.elapsedRealtime()
                                                    ) {
                                                        "Request expired; try again"
                                                    }
                                                    require(
                                                        Caller.resolve(
                                                                this@InteractionActivity,
                                                                flow.caller.uid,
                                                            )
                                                            .identity == flow.caller.identity
                                                    ) {
                                                        "App identity changed"
                                                    }
                                                    val data = Intent(flow.request)
                                                    when (flow.mode) {
                                                        "register" ->
                                                            repo.registrations.register(flow.caller)
                                                        "approve" -> {
                                                            require(
                                                                repo.registrations.registered(
                                                                    flow.caller
                                                                )
                                                            ) {
                                                                "App registration revoked"
                                                            }
                                                            if (!repo.unlocked)
                                                                repo.unlock(password)
                                                            if (keyPassword.isNotEmpty())
                                                                repo.unlockProtected(
                                                                    flow.key,
                                                                    keyPassword,
                                                                )
                                                            repo.preferences
                                                                .edit()
                                                                .apply {
                                                                    flow.caller.apps.forEach {
                                                                        putInt(
                                                                            "approval-policy:${it.packageName}",
                                                                            rememberPolicy,
                                                                        )
                                                                    }
                                                                }
                                                                .apply()
                                                            data.putExtra(
                                                                APPROVAL_TOKEN,
                                                                repo.approvals.approve(
                                                                    flow.caller,
                                                                    data.action!!,
                                                                    flow.key,
                                                                    when (rememberPolicy) {
                                                                        1 -> 300_000L
                                                                        2 -> Long.MAX_VALUE
                                                                        else -> 0L
                                                                    },
                                                                ),
                                                            )
                                                        }
                                                        "sign-picker" -> {
                                                            val key = keys.first {
                                                                it.id == selected.single()
                                                            }
                                                            data
                                                                .putExtra(EXTRA_SIGN_KEY_ID, key.id)
                                                                .putExtra(
                                                                    RESULT_PRIMARY_USER_ID,
                                                                    key.userId,
                                                                )
                                                                .putExtra(
                                                                    RESULT_KEY_CREATION_TIME,
                                                                    key.certificate.publicKey
                                                                        .creationTime
                                                                        .time,
                                                                )
                                                        }
                                                        else ->
                                                            data
                                                                .putExtra(
                                                                    EXTRA_KEY_IDS,
                                                                    selected.toLongArray(),
                                                                )
                                                                .putExtra(
                                                                    EXTRA_KEY_IDS_SELECTED,
                                                                    selected.toLongArray(),
                                                                )
                                                                .putExtra(
                                                                    RESULT_KEY_IDS,
                                                                    selected.toLongArray(),
                                                                )
                                                    }
                                                    data
                                                }
                                            password = ""
                                            keyPassword = ""
                                            setResult(Activity.RESULT_OK, result)
                                            finish()
                                        } catch (e: Exception) {
                                            error = e.message
                                            busy = false
                                        }
                                    }
                                },
                            ) {
                                Text(if (flow.mode == "register") "Allow" else "Continue")
                            }
                        }
                    }
                }
            }
        }
    }
}
