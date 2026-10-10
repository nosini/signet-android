// SPDX-License-Identifier: GPL-3.0-or-later
@file:Suppress("DEPRECATION")

package eu.nosini.signet.api

import android.content.Intent
import eu.nosini.signet.IndexedKey
import eu.nosini.signet.crypto.Crypto
import java.io.*
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.openintents.openpgp.*
import org.openintents.openpgp.util.OpenPgpApi.*

interface KeyBackend {
    fun keys(): List<IndexedKey>

    fun secret(id: Long): PGPSecretKeyRing?

    val unlocked: Boolean

    fun peers(caller: Caller): List<IndexedKey> = emptyList()

    fun updatePeer(caller: Caller, address: String, bytes: ByteArray, date: Long)
}

class OpenPgpRequestHandler(
    private val backend: KeyBackend,
    private val registrations: Registrations,
    private val approvals: Approvals,
    private val interaction: (String, Caller, Intent, Long) -> Intent,
) {
    companion object {
        fun success() = Intent().putExtra(RESULT_CODE, RESULT_CODE_SUCCESS)

        fun failure(message: String, code: Int = OpenPgpError.GENERIC_ERROR) =
            Intent()
                .putExtra(RESULT_CODE, RESULT_CODE_ERROR)
                .putExtra(RESULT_ERROR, OpenPgpError(code, message))

        fun email(userId: String): String =
            userId.substringAfterLast('<', userId).substringBefore('>').trim().lowercase()
    }

    fun handle(request: Intent, input: InputStream?, output: OutputStream, caller: Caller): Intent {
        return try {
            request.setExtrasClassLoader(OpenPgpApiClassLoader)
            if (request.getIntExtra(EXTRA_API_VERSION, -1) !in 7..11)
                return failure(
                    "Unsupported OpenPGP API version",
                    OpenPgpError.INCOMPATIBLE_API_VERSIONS,
                )
            val action = request.action ?: error("Missing action")
            if (!registrations.registered(caller))
                interaction("register", caller, Intent(request), 0)
            else if (action == ACTION_CHECK_PERMISSION) success()
            else execute(request, input, output, caller, action)
        } catch (e: Exception) {
            failure(e.message ?: "OpenPGP operation failed")
        }
    }

    private fun decoder(input: InputStream): InputStream =
        PGPUtil.getDecoderStream(
            object : FilterInputStream(input) {
                override fun markSupported() = false
            }
        )

    private fun charset(input: BufferedInputStream): String? {
        input.mark(1024 * 1024)
        val stream = decoder(input)
        val value =
            (stream as? org.bouncycastle.bcpg.ArmoredInputStream)
                ?.armorHeaders
                ?.firstOrNull { it.startsWith("Charset:", true) }
                ?.substringAfter(':')
                ?.trim()
        input.reset()
        return value?.takeIf {
            it.length <= 100 &&
                runCatching { java.nio.charset.Charset.isSupported(it) }.getOrDefault(false)
        }
    }

    private fun keys(caller: Caller) = backend.keys() + backend.peers(caller)

    private fun find(id: Long, caller: Caller) =
        keys(caller).find { key ->
            key.id == id || key.certificate.publicKeys.asSequence().any { it.keyID == id }
        }

    private fun recipients(request: Intent, caller: Caller): List<IndexedKey>? {
        val ids =
            request.getLongArrayExtra(EXTRA_KEY_IDS_SELECTED)
                ?: request.getLongArrayExtra(EXTRA_KEY_IDS)
        if (ids != null) return ids.map { find(it, caller) ?: return null }.distinctBy { it.id }
        val emails = request.getStringArrayExtra(EXTRA_USER_IDS) ?: return emptyList()
        return emails
            .map { address ->
                keys(caller)
                    .filter {
                        (if (it.peerAddress != null) it.peerAddress == email(address)
                        else it.info.validUserIds.any { user -> email(user) == email(address) }) &&
                            it.info
                                .getEncryptionSubkeys(
                                    org.pgpainless.algorithm.EncryptionPurpose.ANY
                                )
                                .isNotEmpty()
                    }
                    .singleOrNull() ?: return null
            }
            .distinctBy { it.id }
    }

    private fun execute(
        request: Intent,
        rawInput: InputStream?,
        output: OutputStream,
        caller: Caller,
        action: String,
    ): Intent {
        val keys = keys(caller)
        when (action) {
            ACTION_GET_SIGN_KEY_ID,
            ACTION_GET_SIGN_KEY_ID_LEGACY -> {
                val id = request.getLongExtra(EXTRA_SIGN_KEY_ID, 0)
                val key =
                    find(id, caller)?.takeIf { it.own && it.info.signingSubkeys.isNotEmpty() }
                        ?: return interaction("sign-picker", caller, Intent(request), 0)
                return success()
                    .putExtra(EXTRA_SIGN_KEY_ID, key.id)
                    .putExtra(RESULT_PRIMARY_USER_ID, key.userId)
                    .putExtra(RESULT_KEY_CREATION_TIME, key.certificate.publicKey.creationTime.time)
            }
            ACTION_GET_KEY_IDS -> {
                val chosen =
                    recipients(request, caller)
                        ?: return interaction("recipient-picker", caller, Intent(request), 0)
                return success().putExtra(RESULT_KEY_IDS, chosen.map { it.id }.toLongArray())
            }
            ACTION_GET_KEY -> {
                val user = request.getStringExtra(EXTRA_USER_ID)
                val key =
                    if (request.hasExtra(EXTRA_KEY_ID))
                        find(request.getLongExtra(EXTRA_KEY_ID, 0), caller)
                    else
                        user?.let { address ->
                            keys
                                .filter { key ->
                                    if (key.peerAddress != null) key.peerAddress == email(address)
                                    else
                                        key.info.validUserIds.any {
                                            it == address || email(it) == email(address)
                                        }
                                }
                                .singleOrNull()
                        }
                requireNotNull(key) { "Key is missing or ambiguous; import it into Signet" }
                val certificate =
                    if (request.getBooleanExtra(EXTRA_MINIMIZE, false))
                        Crypto.minimize(
                            key.certificate,
                            request.getStringExtra(EXTRA_MINIMIZE_USER_ID)
                                ?: user
                                ?: key.peerAddress,
                        )
                    else key.certificate
                output.write(
                    if (request.getBooleanExtra(EXTRA_REQUEST_ASCII_ARMOR, false))
                        Crypto.armor(certificate).toByteArray()
                    else certificate.encoded
                )
                return success()
            }
            ACTION_BACKUP ->
                return failure("Provider backup is not supported; back up the encrypted vault")
            ACTION_QUERY_AUTOCRYPT_STATUS -> {
                val chosen = recipients(request, caller)
                return success()
                    .putExtra(
                        RESULT_AUTOCRYPT_STATUS,
                        if (chosen.isNullOrEmpty()) AUTOCRYPT_STATUS_UNAVAILABLE
                        else AUTOCRYPT_STATUS_AVAILABLE,
                    )
            }
            ACTION_UPDATE_AUTOCRYPT_PEER -> {
                val address =
                    request.getStringExtra(EXTRA_AUTOCRYPT_PEER_ID)
                        ?: error("Missing Autocrypt address")
                val update =
                    request.getParcelableExtra<AutocryptPeerUpdate>(EXTRA_AUTOCRYPT_PEER_UPDATE)
                        ?: error("Missing Autocrypt update")
                if (update.hasKeyData())
                    backend.updatePeer(caller, address, update.keyData, update.effectiveDate.time)
                return success()
            }
        }
        val signing =
            action in
                setOf(
                    ACTION_SIGN,
                    ACTION_CLEARTEXT_SIGN,
                    ACTION_DETACHED_SIGN,
                    ACTION_SIGN_AND_ENCRYPT,
                )
        val decrypting = action in setOf(ACTION_DECRYPT_VERIFY, ACTION_DECRYPT_METADATA)
        require(signing || decrypting || action == ACTION_ENCRYPT) { "Unsupported OpenPGP action" }
        val input = BufferedInputStream(rawInput ?: error("Missing input stream"), 8192)
        var signingId = request.getLongExtra(EXTRA_SIGN_KEY_ID, 0)
        if (
            signing &&
                find(signingId, caller)?.takeIf { it.own && it.info.signingSubkeys.isNotEmpty() } ==
                    null
        )
            return interaction("sign-picker", caller, Intent(request), 0)
        var decryptId = 0L
        var encrypted = false
        if (decrypting && !request.hasExtra(EXTRA_DETACHED_SIGNATURE)) {
            input.mark(1024 * 1024)
            val prefix = ByteArray(64)
            val prefixLength = input.read(prefix)
            input.reset()
            input.mark(1024 * 1024)
            val cleartextSigned =
                prefixLength > 0 &&
                    String(prefix, 0, prefixLength).startsWith("-----BEGIN PGP SIGNED MESSAGE-----")
            val objects =
                if (cleartextSigned) null
                else PGPObjectFactory(decoder(input), BcKeyFingerprintCalculator())
            var obj = objects?.nextObject()
            if (obj is PGPMarker) obj = objects?.nextObject()
            if (obj is PGPEncryptedDataList) {
                encrypted = true
                val recipientIds =
                    obj.encryptedDataObjects
                        .asSequence()
                        .filterIsInstance<PGPPublicKeyEncryptedData>()
                        .map { it.keyID }
                        .toList()
                decryptId =
                    keys
                        .firstOrNull { key ->
                            key.own &&
                                key.certificate.publicKeys.asSequence().any {
                                    it.keyID in recipientIds
                                }
                        }
                        ?.id ?: 0L
                require(decryptId != 0L || recipientIds.contains(0L)) {
                    "No matching secret key in this vault"
                }
            }
            input.reset()
        }
        val keyId = if (signing) find(signingId, caller)!!.id else decryptId
        if (signing || encrypted) {
            if (
                !backend.unlocked ||
                    !approvals.consume(
                        caller,
                        action,
                        keyId,
                        request.getStringExtra(APPROVAL_TOKEN),
                    )
            )
                return interaction("approve", caller, Intent(request), keyId)
        }
        if (decrypting) {
            val secrets =
                if (encrypted)
                    (if (decryptId == 0L)
                        keys.filter { it.own }.mapNotNull { backend.secret(it.id) }
                    else listOfNotNull(backend.secret(decryptId)))
                else emptyList()
            val countOutput =
                object : OutputStream() {
                    var count = 0L

                    override fun write(b: Int) {
                        count++
                        if (action != ACTION_DECRYPT_METADATA) output.write(b)
                    }

                    override fun write(b: ByteArray, off: Int, len: Int) {
                        count += len
                        if (action != ACTION_DECRYPT_METADATA) output.write(b, off, len)
                    }
                }
            val encoding = if (request.hasExtra(EXTRA_DETACHED_SIGNATURE)) null else charset(input)
            val metadata =
                Crypto.consume(
                    input,
                    countOutput,
                    keys.map { it.certificate },
                    secrets,
                    request.getByteArrayExtra(EXTRA_DETACHED_SIGNATURE),
                )
            val verified = metadata.verifiedSignatures.firstOrNull()
            val signature =
                if (verified != null) {
                    val issuer = find(verified.signature.keyID, caller)
                    val users = issuer?.info?.userIds.orEmpty()
                    val sender = request.getStringExtra(EXTRA_SENDER_ADDRESS)
                    val senderStatus =
                        if (sender == null) OpenPgpSignatureResult.SenderStatusResult.UNKNOWN
                        else if (
                            issuer?.info?.validUserIds.orEmpty().any { email(it) == email(sender) }
                        )
                            OpenPgpSignatureResult.SenderStatusResult.USER_ID_UNCONFIRMED
                        else OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING
                    OpenPgpSignatureResult.createWithValidSignature(
                        OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
                        issuer?.userId,
                        issuer?.id ?: verified.signature.keyID,
                        users,
                        emptyList(),
                        senderStatus,
                        verified.signature.creationTime,
                    )
                } else if (metadata.hasSignature) {
                    val missing =
                        metadata.rejectedSignatures.firstOrNull {
                            find(it.signature.keyID, caller) == null
                        }
                    if (missing != null)
                        OpenPgpSignatureResult.createWithKeyMissing(
                            missing.signature.keyID,
                            missing.signature.creationTime,
                        )
                    else OpenPgpSignatureResult.createWithInvalidSignature()
                } else OpenPgpSignatureResult.createWithNoSignature()
            return success()
                .putExtra(RESULT_SIGNATURE, signature)
                .putExtra(
                    RESULT_DECRYPTION,
                    OpenPgpDecryptionResult(
                        if (metadata.isEncrypted) OpenPgpDecryptionResult.RESULT_ENCRYPTED
                        else OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED
                    ),
                )
                .putExtra(
                    RESULT_METADATA,
                    OpenPgpMetadata(
                        metadata.filename ?: "",
                        "application/octet-stream",
                        metadata.modificationDate?.time ?: 0L,
                        countOutput.count,
                        encoding,
                    ),
                )
                .apply { if (encoding != null) putExtra(RESULT_CHARSET, encoding) }
        }
        val selected =
            if (action == ACTION_ENCRYPT || action == ACTION_SIGN_AND_ENCRYPT) {
                val matches = recipients(request, caller)
                if (
                    matches.isNullOrEmpty() &&
                        request.getBooleanExtra(EXTRA_OPPORTUNISTIC_ENCRYPTION, false)
                )
                    return failure(
                        "Missing keys in opportunistic mode",
                        OpenPgpError.OPPORTUNISTIC_MISSING_KEYS,
                    )
                matches ?: return interaction("recipient-picker", caller, Intent(request), 0)
            } else emptyList()
        val recipientCerts = selected.map { it.certificate }.toMutableList()
        if (action == ACTION_SIGN_AND_ENCRYPT)
            find(signingId, caller)?.let { recipientCerts.add(it.certificate) }
        if (action == ACTION_ENCRYPT || action == ACTION_SIGN_AND_ENCRYPT)
            require(recipientCerts.isNotEmpty()) { "No recipients selected" }
        val signer =
            if (signing) backend.secret(signingId) ?: error("Signing key unavailable") else null
        val detached = action == ACTION_DETACHED_SIGN
        val signature =
            Crypto.produce(
                input,
                if (detached)
                    object : OutputStream() {
                        override fun write(b: Int) {}
                    }
                else output,
                recipientCerts.distinctBy { Crypto.fingerprint(it) },
                signer,
                request.getBooleanExtra(EXTRA_REQUEST_ASCII_ARMOR, true),
                detached,
                action == ACTION_SIGN || action == ACTION_CLEARTEXT_SIGN,
                request.getStringExtra(EXTRA_ORIGINAL_FILENAME) ?: "",
                request.getBooleanExtra(EXTRA_ENABLE_COMPRESSION, true),
            )
        return success().apply {
            if (detached) {
                putExtra(RESULT_DETACHED_SIGNATURE, signature)
                val packet =
                    PGPObjectFactory(
                            PGPUtil.getDecoderStream(signature!!.inputStream()),
                            BcKeyFingerprintCalculator(),
                        )
                        .nextObject() as PGPSignatureList
                putExtra(
                    RESULT_SIGNATURE_MICALG,
                    when (packet[0].hashAlgorithm) {
                        8 -> "pgp-sha256"
                        9 -> "pgp-sha384"
                        10 -> "pgp-sha512"
                        11 -> "pgp-sha224"
                        else -> error("Unsupported signature hash")
                    },
                )
            }
        }
    }

    private val OpenPgpApiClassLoader
        get() = OpenPgpError::class.java.classLoader
}
