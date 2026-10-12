// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.*
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.navigation.compose.*
import eu.nosini.signet.crypto.Crypto
import eu.nosini.signet.vault.*
import java.io.File
import kotlinx.coroutines.*

class MainActivity : FragmentActivity() {
    private val repo
        get() = (application as SignetApplication).repository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent { SignetTheme { SignetUi() } }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        repo.touch()
    }

    @Composable
    private fun SignetUi() {
        val nav = rememberNavController()
        val scope = rememberCoroutineScope()
        val updates by repo.updates.collectAsState()
        var message by remember { mutableStateOf<String?>(null) }
        var notice by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        var importText by remember {
            mutableStateOf(intent.getStringExtra(Intent.EXTRA_TEXT) ?: "")
        }
        var importPass by remember { mutableStateOf("") }
        var exportText by remember { mutableStateOf("") }
        var selected by remember { mutableStateOf<IndexedKey?>(null) }
        var password by remember { mutableStateOf("") }
        var repeated by remember { mutableStateOf("") }
        var name by remember { mutableStateOf("") }
        var email by remember { mutableStateOf("") }
        var rsa by remember { mutableStateOf(false) }
        var davUrl by remember { mutableStateOf(repo.preferences.getString("dav-url", "")!!) }
        var davUser by remember { mutableStateOf(repo.preferences.getString("dav-user", "")!!) }
        var davPass by remember { mutableStateOf("") }
        var davConnected by remember { mutableStateOf(davUrl.isNotBlank()) }
        var davDialog by remember { mutableStateOf(false) }
        var biometricOn by remember {
            mutableStateOf(repo.preferences.getBoolean("biometric", false))
        }
        var biometricDialog by remember { mutableStateOf(false) }
        var biometricPassword by remember { mutableStateOf("") }
        fun openDavDialog() {
            message = null
            davDialog = true
        }
        // `action` runs off the main thread and returns an optional success notice;
        // `after` runs on the main thread once it succeeds.
        fun work(after: () -> Unit = {}, action: () -> String?) {
            busy = true
            message = null
            notice = null
            scope.launch {
                try {
                    notice = withContext(Dispatchers.IO) { action() }
                    after()
                } catch (e: Exception) {
                    message = e.message ?: "Operation failed"
                } finally {
                    busy = false
                }
            }
        }
        val filePicker =
            rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                if (uri != null)
                    work {
                        contentResolver.openInputStream(uri)!!.use {
                            repo.open(readBounded(it, 256 * 1024 * 1024))
                        }
                        "Vault file opened. Enter its master password to unlock it."
                    }
            }
        val keyPicker =
            rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                if (uri != null)
                    work {
                        val bytes =
                            contentResolver.openInputStream(uri)!!.use {
                                readBounded(it, 1024 * 1024)
                            }
                        try {
                            atomicWrite(File(filesDir, "keyfile"), bytes)
                        } finally {
                            bytes.fill(0)
                        }
                        "Key file selected"
                    }
            }
        val importPicker =
            rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                if (uri != null)
                    scope.launch {
                        runCatching {
                            withContext(Dispatchers.IO) {
                                contentResolver.openInputStream(uri)!!.use {
                                    String(readBounded(it, 16 * 1024 * 1024))
                                }
                            }
                        }
                            .onSuccess { importText = it }
                            .onFailure { message = it.message }
                    }
            }
        val exportPicker =
            rememberLauncherForActivityResult(
                ActivityResultContracts.CreateDocument("application/pgp-keys")
            ) { uri ->
                if (uri != null)
                    work {
                        contentResolver.openOutputStream(uri, "wt")!!.use {
                            it.write(exportText.toByteArray())
                        }
                        exportText = ""
                        "Key exported"
                    }
                else exportText = ""
            }
        val shareUri = remember {
            intent
                .takeIf { it.action == Intent.ACTION_SEND }
                ?.let {
                    @Suppress("DEPRECATION")
                    it.getParcelableExtra<android.net.Uri>(Intent.EXTRA_STREAM)
                } ?: intent.data
        }
        LaunchedEffect(shareUri) {
            shareUri?.let { uri ->
                runCatching {
                    require(
                        uri.scheme == "content" &&
                            packageManager
                                .resolveContentProvider(uri.authority ?: "", 0)
                                ?.packageName != packageName
                    ) {
                        "Import requires an external content URI"
                    }
                    withContext(Dispatchers.IO) {
                        contentResolver.openInputStream(uri)!!.use {
                            String(readBounded(it, 16 * 1024 * 1024))
                        }
                    }
                }
                    .onSuccess {
                        importText = it
                        nav.navigate("import")
                    }
                    .onFailure { message = it.message }
            }
        }
        Surface {
            Column(Modifier.fillMaxSize().padding(WindowInsets.safeDrawing.asPaddingValues())) {
                Row(
                    Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    TextButton(onClick = { nav.navigate("keys") }) {
                        Text("Signet", style = MaterialTheme.typography.titleLarge)
                    }
                    TextButton(onClick = { nav.navigate("settings") }) { Text("Settings") }
                    if (repo.unlocked)
                        TextButton(
                            onClick = {
                                repo.lock()
                                password = ""
                            }
                        ) {
                            Text("Lock")
                        }
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                (message ?: repo.error)?.let {
                    Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error)
                }
                notice?.let {
                    Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.primary)
                }
                if (davDialog)
                    AlertDialog(
                        onDismissRequest = {
                            if (!busy) {
                                davDialog = false
                                davPass = ""
                            }
                        },
                        title = { Text(if (davConnected) "WebDAV settings" else "Connect WebDAV") },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                OutlinedTextField(
                                    davUrl,
                                    { davUrl = it },
                                    label = { Text("HTTPS URL of the KDBX file") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                OutlinedTextField(
                                    davUser,
                                    { davUser = it },
                                    label = { Text("Username") },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                PasswordField(davPass, { davPass = it }, "Password")
                                if (davConnected)
                                    Text(
                                        "Leave empty to keep the current password.",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                                message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                            }
                        },
                        confirmButton = {
                            Button(
                                enabled = !busy && davUrl.isNotBlank(),
                                onClick = {
                                    val download = !repo.file.exists()
                                    val keepPassword = davConnected && davPass.isEmpty()
                                    work(
                                        after = {
                                            davDialog = false
                                            if (download && nav.currentDestination?.route != "keys")
                                                nav.navigate("keys")
                                        }
                                    ) {
                                        val pass =
                                            if (keepPassword) repo.dav()?.password ?: "" else davPass
                                        repo.configureDav(davUrl.trim(), davUser, pass)
                                        davPass = ""
                                        davConnected = true
                                        if (download) {
                                            repo.open(WebDav().download(repo.dav()!!))
                                            "Vault downloaded. Enter its master password to unlock it."
                                        } else if (repo.unlocked) {
                                            repo.sync()
                                            "WebDAV settings saved and vault synced"
                                        } else "WebDAV settings saved. Sync starts after unlocking."
                                    }
                                },
                            ) {
                                Text(
                                    if (!repo.file.exists()) "Connect and download"
                                    else if (davConnected) "Save"
                                    else "Connect"
                                )
                            }
                        },
                        dismissButton = {
                            TextButton(
                                enabled = !busy,
                                onClick = {
                                    davDialog = false
                                    davPass = ""
                                    message = null
                                },
                            ) {
                                Text("Cancel")
                            }
                        },
                    )
                if (biometricDialog)
                    AlertDialog(
                        onDismissRequest = {
                            if (!busy) {
                                biometricDialog = false
                                biometricPassword = ""
                            }
                        },
                        title = { Text("Enable biometric unlock") },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text(
                                    "Enter your master password. Signet keeps it in Android Keystore, available only after biometric authentication."
                                )
                                PasswordField(
                                    biometricPassword,
                                    { biometricPassword = it },
                                    "Master password",
                                )
                                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                                message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                            }
                        },
                        confirmButton = {
                            Button(
                                enabled = !busy && biometricPassword.isNotEmpty(),
                                onClick = {
                                    val entered = biometricPassword
                                    busy = true
                                    message = null
                                    notice = null
                                    scope.launch {
                                        try {
                                            withContext(Dispatchers.IO) {
                                                repo.checkPassword(entered)
                                            }
                                        } catch (e: Exception) {
                                            busy = false
                                            message = e.message ?: "Wrong master password"
                                            return@launch
                                        }
                                        busy = false
                                        biometricDialog = false
                                        biometricPassword = ""
                                        biometric(
                                            repo,
                                            entered,
                                            done = {
                                                biometricOn = true
                                                notice = "Biometric unlock enabled"
                                            },
                                            failure = { message = it },
                                        )
                                    }
                                },
                            ) {
                                Text("Continue")
                            }
                        },
                        dismissButton = {
                            TextButton(
                                enabled = !busy,
                                onClick = {
                                    biometricDialog = false
                                    biometricPassword = ""
                                    message = null
                                },
                            ) {
                                Text("Cancel")
                            }
                        },
                    )
                NavHost(
                    navController = nav,
                    startDestination = "keys",
                    modifier = Modifier.weight(1f),
                ) {
                    composable("keys") {
                        Column(
                            Modifier.fillMaxSize()
                                .padding(16.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (!repo.file.exists()) {
                                Text("Keep your OpenPGP keys in an encrypted KeePass vault.")
                                TextButton(onClick = { keyPicker.launch(arrayOf("*/*")) }) {
                                    Text("Choose optional key file")
                                }
                                PasswordField(password, { password = it }, "Master password")
                                PasswordField(repeated, { repeated = it }, "Repeat password")
                                Button(
                                    enabled = !busy,
                                    onClick = {
                                        if (password != repeated || password.isEmpty())
                                            message = "Passwords must match and be nonempty"
                                        else {
                                            val epoch = repo.sessionEpoch
                                            work {
                                                repo.create(password, epoch)
                                                password = ""
                                                repeated = ""
                                                null
                                            }
                                        }
                                    },
                                ) {
                                    Text("Create new vault")
                                }
                                OutlinedButton(onClick = { filePicker.launch(arrayOf("*/*")) }) {
                                    Text("Open KDBX file")
                                }
                                OutlinedButton(onClick = { openDavDialog() }) {
                                    Text("Connect WebDAV")
                                }
                            } else if (!repo.unlocked) {
                                Text("Vault locked")
                                PasswordField(password, { password = it }, "Master password")
                                Button(
                                    enabled = !busy,
                                    onClick = {
                                        val epoch = repo.sessionEpoch
                                        work {
                                            repo.unlock(password, epoch)
                                            password = ""
                                            null
                                        }
                                    },
                                ) {
                                    Text("Unlock")
                                }
                                if (repo.preferences.getBoolean("biometric", false))
                                    OutlinedButton(
                                        onClick = {
                                            message = null
                                            notice = null
                                            biometric(
                                                repo,
                                                started = { busy = true },
                                                done = { busy = false },
                                                failure = {
                                                    busy = false
                                                    message = it
                                                },
                                            )
                                        }
                                    ) {
                                        Text("Unlock with biometrics")
                                    }
                                TextButton(onClick = { keyPicker.launch(arrayOf("*/*")) }) {
                                    Text("Choose optional key file")
                                }
                                if (File(filesDir, "keyfile").exists())
                                    TextButton(onClick = { File(filesDir, "keyfile").delete() }) {
                                        Text("Remove key file")
                                    }
                            } else
                                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Button(onClick = { nav.navigate("import") }) { Text("Import") }
                                    OutlinedButton(onClick = { nav.navigate("generate") }) {
                                        Text("Generate")
                                    }
                                    TextButton(
                                        enabled = !busy,
                                        onClick = {
                                            work {
                                                repo.sync()
                                                if (repo.dav() == null) "WebDAV is not set up"
                                                else "Synced"
                                            }
                                        },
                                    ) {
                                        Text("Sync")
                                    }
                                }
                            repo.keys().forEach { key ->
                                Card(
                                    onClick = {
                                        selected = key
                                        nav.navigate("detail")
                                    },
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Column(Modifier.padding(16.dp)) {
                                        Text(
                                            displayText(key.userId),
                                            style = MaterialTheme.typography.titleMedium,
                                        )
                                        Text(
                                            "${if(key.own) "Own key" else "Contact"} · ${key.fingerprint.takeLast(16)}"
                                        )
                                        Text(
                                            listOfNotNull(
                                                    if (key.info.isSigningCapable) "Sign" else null,
                                                    if (
                                                        key.info.isUsableForEncryption(
                                                            org.pgpainless.algorithm
                                                                .EncryptionPurpose
                                                                .ANY
                                                        )
                                                    )
                                                        "Encrypt"
                                                    else null,
                                                )
                                                .joinToString(" · ")
                                        )
                                        Text(
                                            if (key.certificate.publicKey.hasRevocation()) "Revoked"
                                            else
                                                "Expires: ${key.info.primaryKeyExpirationDate ?: "never"}"
                                        )
                                    }
                                }
                            }
                            val synced = repo.preferences.getLong("last-sync", 0)
                            if (synced > 0) Text("Last sync: ${java.util.Date(synced)}")
                        }
                    }
                    composable("import") {
                        Column(
                            Modifier.fillMaxSize()
                                .padding(16.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Text(
                                "Import OpenPGP key",
                                style = MaterialTheme.typography.headlineSmall,
                            )
                            OutlinedTextField(
                                importText,
                                { importText = it },
                                label = { Text("Armored public or secret key") },
                                modifier = Modifier.fillMaxWidth().height(220.dp),
                            )
                            PasswordField(
                                importPass,
                                { importPass = it },
                                "OpenPGP key passphrase, if protected",
                            )
                            Row {
                                TextButton(
                                    onClick = {
                                        @Suppress("DEPRECATION")
                                        val text =
                                            (getSystemService(CLIPBOARD_SERVICE)
                                                    as ClipboardManager)
                                                .primaryClip
                                                ?.getItemAt(0)
                                                ?.coerceToText(this@MainActivity)
                                        importText = text?.toString() ?: ""
                                    }
                                ) {
                                    Text("Paste")
                                }
                                TextButton(onClick = { importPicker.launch(arrayOf("*/*")) }) {
                                    Text("Choose file")
                                }
                            }
                            Button(
                                enabled = repo.unlocked && !busy,
                                onClick = {
                                    work {
                                        repo.importKey(importText, importPass)
                                        importText = ""
                                        importPass = ""
                                        "Key imported"
                                    }
                                },
                            ) {
                                Text("Import")
                            }
                            if (!repo.unlocked) Text("Unlock your vault on the Keys screen first.")
                        }
                    }
                    composable("generate") {
                        Column(
                            Modifier.fillMaxSize().padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Text("Generate key", style = MaterialTheme.typography.headlineSmall)
                            OutlinedTextField(name, { name = it }, label = { Text("Name") })
                            OutlinedTextField(email, { email = it }, label = { Text("Email") })
                            Row {
                                Checkbox(rsa, { rsa = it })
                                Text(
                                    "RSA 4096 (default: Ed25519/X25519)",
                                    Modifier.padding(top = 12.dp),
                                )
                            }
                            Button(
                                enabled = repo.unlocked && !busy,
                                onClick = {
                                    if (
                                        name.isBlank() ||
                                            !email.contains('@') ||
                                            (name + email).any {
                                                it == '<' || it == '>' || it.isISOControl()
                                            }
                                    )
                                        message =
                                            "Enter a name and email without control characters or angle brackets"
                                    else
                                        work {
                                            val key = Crypto.generate("$name <$email>", rsa)
                                            repo.importKey(Crypto.armor(key))
                                            "Key generated"
                                        }
                                },
                            ) {
                                Text("Generate")
                            }
                        }
                    }
                    composable("detail") {
                        selected?.let { key ->
                            Column(
                                Modifier.fillMaxSize()
                                    .padding(16.dp)
                                    .verticalScroll(rememberScrollState()),
                                verticalArrangement = Arrangement.spacedBy(12.dp),
                            ) {
                                Text(
                                    displayText(key.userId),
                                    style = MaterialTheme.typography.headlineSmall,
                                )
                                Text(key.fingerprint.chunked(4).joinToString(" "))
                                key.info.userIds.forEach { Text(displayText(it)) }
                                key.certificate.publicKeys.asSequence().forEach { sub ->
                                    Text(
                                        "${sub.keyID.toULong().toString(16).uppercase()} · algorithm ${sub.algorithm} · ${sub.bitStrength} bits\nExpires: ${key.info.getSubkeyExpirationDate(sub.keyID) ?: "never"}"
                                    )
                                }
                                Button(
                                    onClick = {
                                        exportText = key.armor
                                        exportPicker.launch("${key.fingerprint}.asc")
                                    }
                                ) {
                                    Text("Export public key")
                                }
                                TextButton(
                                    onClick = {
                                        (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager)
                                            .setPrimaryClip(
                                                ClipData.newPlainText(
                                                    "OpenPGP public key",
                                                    key.armor,
                                                )
                                            )
                                    }
                                ) {
                                    Text("Copy public key")
                                }
                                TextButton(
                                    onClick = {
                                        startActivity(
                                            Intent.createChooser(
                                                Intent(Intent.ACTION_SEND)
                                                    .setType("application/pgp-keys")
                                                    .putExtra(Intent.EXTRA_TEXT, key.armor),
                                                "Share public key",
                                            )
                                        )
                                    }
                                ) {
                                    Text("Share public key")
                                }
                                if (key.own) {
                                    Text(
                                        "Exporting a secret key creates an unencrypted copy. Re-enter the vault password to confirm."
                                    )
                                    PasswordField(password, { password = it }, "Master password")
                                    Button(
                                        enabled = repo.unlocked && !busy,
                                        onClick = {
                                            scope.launch {
                                                try {
                                                    exportText =
                                                        withContext(Dispatchers.IO) {
                                                            repo.reauthenticatedExport(
                                                                password,
                                                                key.id,
                                                            )
                                                        }
                                                    password = ""
                                                    exportPicker.launch(
                                                        "${key.fingerprint}-secret.asc"
                                                    )
                                                } catch (e: Exception) {
                                                    message = e.message
                                                }
                                            }
                                        },
                                    ) {
                                        Text("Confirm and export secret key")
                                    }
                                }
                                if (key.entry != null && !key.entry.startsWith("peer:"))
                                    OutlinedButton(
                                        enabled = repo.unlocked && !busy,
                                        onClick = {
                                            work {
                                                repo.delete(key.entry)
                                                null
                                            }
                                            nav.navigate("keys")
                                        },
                                    ) {
                                        Text("Move to recycle bin or delete")
                                    }
                            }
                        }
                    }
                    composable("settings") {
                        Column(
                            Modifier.fillMaxSize()
                                .padding(16.dp)
                                .verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            Text("Settings", style = MaterialTheme.typography.headlineSmall)
                            SwitchRow(
                                "WebDAV sync",
                                if (davConnected)
                                    listOf(davUrl, davUser).filter { it.isNotBlank() }.joinToString(" · ")
                                else "Off",
                                davConnected,
                                enabled = !busy,
                                onChange = { on ->
                                    if (on) openDavDialog()
                                    else {
                                        repo.preferences
                                            .edit()
                                            .remove("dav-url")
                                            .remove("dav-user")
                                            .remove("sync-state")
                                            .apply()
                                        repo.secure.delete("webdav")
                                        davUrl = ""
                                        davUser = ""
                                        davConnected = false
                                        message = null
                                        notice = "WebDAV disconnected"
                                    }
                                },
                            ) {
                                if (davConnected)
                                    IconButton(enabled = !busy, onClick = { openDavDialog() }) {
                                        Icon(
                                            painterResource(R.drawable.ic_settings),
                                            contentDescription = "Edit WebDAV settings",
                                        )
                                    }
                            }
                            var lockMinutes by remember {
                                mutableStateOf(
                                    repo.preferences.getLong("lock-minutes", 5).toString()
                                )
                            }
                            var syncMinutes by remember {
                                mutableStateOf(
                                    repo.preferences.getLong("sync-minutes", 5).toString()
                                )
                            }
                            OutlinedTextField(
                                lockMinutes,
                                { lockMinutes = it },
                                label = { Text("Idle lock, minutes") },
                            )
                            OutlinedTextField(
                                syncMinutes,
                                { syncMinutes = it },
                                label = { Text("Sync interval while unlocked, minutes") },
                            )
                            Button(
                                onClick = {
                                    val lock = lockMinutes.toLongOrNull()
                                    val sync = syncMinutes.toLongOrNull()
                                    if (
                                        lock == null ||
                                            sync == null ||
                                            lock !in 1..1440 ||
                                            sync !in 1..1440
                                    )
                                        message = "Enter 1–1440 minutes"
                                    else {
                                        repo.preferences
                                            .edit()
                                            .putLong("lock-minutes", lock)
                                            .putLong("sync-minutes", sync)
                                            .apply()
                                        message = null
                                        notice = "Intervals saved"
                                    }
                                }
                            ) {
                                Text("Save intervals")
                            }
                            var screenLock by remember {
                                mutableStateOf(repo.preferences.getBoolean("lock-screen", true))
                            }
                            SwitchRow(
                                "Lock when screen turns off",
                                null,
                                screenLock,
                                onChange = {
                                    screenLock = it
                                    repo.preferences.edit().putBoolean("lock-screen", it).apply()
                                },
                            )
                            SwitchRow(
                                "Biometric unlock",
                                if (repo.file.exists()) null else "Set up a vault first",
                                biometricOn,
                                enabled = repo.file.exists() && !busy,
                                onChange = { on ->
                                    if (on) {
                                        message = null
                                        biometricDialog = true
                                    }
                                    else {
                                        repo.secure.delete("biometric")
                                        repo.preferences
                                            .edit()
                                            .putBoolean("biometric", false)
                                            .apply()
                                        biometricOn = false
                                        message = null
                                        notice = "Biometric unlock disabled"
                                    }
                                },
                            )
                            Text("Default approval policy")
                            var policy by remember {
                                mutableIntStateOf(repo.preferences.getInt("approval-policy", 0))
                            }
                            listOf("Ask every time", "5 minutes", "Until vault locks")
                                .forEachIndexed { i, label ->
                                    Row {
                                        RadioButton(
                                            policy == i,
                                            onClick = {
                                                policy = i
                                                repo.preferences
                                                    .edit()
                                                    .putInt("approval-policy", i)
                                                    .apply()
                                            },
                                        )
                                        Text(label, Modifier.padding(top = 12.dp))
                                    }
                                }
                            Text("Connected apps", style = MaterialTheme.typography.titleMedium)
                            var appRevision by remember { mutableIntStateOf(0) }
                            remember(appRevision) { repo.registrations.list() }
                                .forEach { (app, certs) ->
                                    Text(app)
                                    Text(
                                        certs.joinToString(),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                    val appPolicy =
                                        repo.preferences.getInt(
                                            "approval-policy:$app",
                                            repo.preferences.getInt("approval-policy", 0),
                                        )
                                    TextButton(
                                        onClick = {
                                            repo.preferences
                                                .edit()
                                                .putInt("approval-policy:$app", (appPolicy + 1) % 3)
                                                .apply()
                                            repo.approvals.clear()
                                            appRevision++
                                        }
                                    ) {
                                        Text(
                                            "Approval: ${listOf("ask every time", "5 minutes", "until vault locks")[appPolicy]}"
                                        )
                                    }
                                    repo.grants.list(app).forEach { grant ->
                                        val key = repo.keys().find { it.fingerprint == grant.fingerprint }
                                        Text(
                                            "Always allowed to ${grant.kind}: " +
                                                (key?.let { displayText(it.userId) + "\n" } ?: "") +
                                                grant.fingerprint.chunked(4).joinToString(" "),
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                        TextButton(
                                            onClick = {
                                                repo.grants.revoke(app, grant)
                                                appRevision++
                                            }
                                        ) {
                                            Text("Stop always allowing")
                                        }
                                    }
                                    TextButton(
                                        onClick = {
                                            repo.registrations.revoke(app)
                                            repo.grants.revokeApp(app)
                                            repo.approvals.clear()
                                            appRevision++
                                        }
                                    ) {
                                        Text("Revoke")
                                    }
                                }
                            Text("Signet ${BuildConfig.VERSION_NAME} · GPL-3.0-or-later")
                            Text(
                                "Source: https://github.com/nosini/signet-android. No analytics. Network access is limited to your configured WebDAV server."
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SwitchRow(
    title: String,
    summary: String?,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit,
    actions: @Composable () -> Unit = {},
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            summary?.let {
                Text(
                    displayText(it),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        actions()
        Switch(checked, onChange, enabled = enabled)
    }
}

@Composable
private fun PasswordField(value: String, changed: (String) -> Unit, label: String) {
    OutlinedTextField(
        value,
        changed,
        label = { Text(label) },
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier.fillMaxWidth(),
    )
}

fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val bytes = ByteArray(8192)
    while (true) {
        val n = input.read(bytes)
        if (n < 0) break
        require(out.size() + n <= limit) { "File is too large" }
        out.write(bytes, 0, n)
    }
    return out.toByteArray()
}

fun displayText(value: String): String =
    value
        .take(240)
        .map { c ->
            if (c.isWhitespace()) ' '
            else if (c.isISOControl() || Character.getType(c) == Character.FORMAT.toInt()) '\uFFFD'
            else c
        }
        .joinToString("")
