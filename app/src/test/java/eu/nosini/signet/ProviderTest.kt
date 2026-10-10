// SPDX-License-Identifier: GPL-3.0-or-later
package eu.nosini.signet

import android.content.Intent
import android.os.Parcel
import eu.nosini.signet.api.*
import eu.nosini.signet.crypto.Crypto
import java.io.ByteArrayOutputStream
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.openintents.openpgp.*
import org.openintents.openpgp.util.OpenPgpApi.*
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = android.app.Application::class)
class ProviderTest {
    private val caller = Caller(1000, listOf(CallerApp("test.app", setOf("cert"), "Test")))
    private val other = Caller(1001, listOf(CallerApp("other.app", setOf("cert"), "Other")))
    private val registrations =
        object : Registrations {
            var known = false

            override fun registered(caller: Caller) =
                known && caller.apps.single().packageName == "test.app"

            override fun register(caller: Caller) {
                known = true
            }

            override fun revoke(packageName: String) {
                known = false
            }

            override fun list() = emptyMap<String, Set<String>>()
        }
    private var now = 100L
    private val approvals = Approvals { now }
    private val key = CryptoTest.modern
    private val indexed = IndexedKey(Crypto.armor(Crypto.publicPart(key)), true)
    private val backend =
        object : KeyBackend {
            override var unlocked = false

            override fun keys() = listOf(indexed)

            override fun secret(id: Long) = if (unlocked && id == indexed.id) key else null

            override fun updatePeer(address: String, bytes: ByteArray, date: Long) {}
        }
    private val handler =
        OpenPgpRequestHandler(backend, registrations, approvals) { mode, _, _, keyId ->
            Intent()
                .putExtra(RESULT_CODE, RESULT_CODE_USER_INTERACTION_REQUIRED)
                .putExtra("mode", mode)
                .putExtra("key", keyId)
        }

    private fun request(action: String) = Intent(action).putExtra(EXTRA_API_VERSION, 11)

    private fun call(request: Intent, bytes: ByteArray? = null): Pair<Intent, ByteArray> {
        val out = ByteArrayOutputStream()
        val result = handler.handle(request, bytes?.inputStream(), out, caller)
        return result to out.toByteArray()
    }

    @Test
    fun unsignedUserIdDoesNotResolveAnEmail() {
        registrations.register(caller)
        val public = Crypto.publicPart(key)
        val bytes = public.encoded
        val primary = public.publicKey.publicKeyPacket.encoded
        val extra = org.bouncycastle.bcpg.UserIDPacket("Victim <victim@example.org>").encoded
        val forged = Crypto.publicKey(primary + extra + bytes.copyOfRange(primary.size, bytes.size))
        val indexed = IndexedKey(Crypto.armor(forged), false)
        assertTrue(indexed.info.userIds.contains("Victim <victim@example.org>"))
        assertFalse(indexed.info.validUserIds.contains("Victim <victim@example.org>"))
        val fake =
            object : KeyBackend {
                override val unlocked = false

                override fun keys() = listOf(indexed)

                override fun secret(id: Long): org.bouncycastle.openpgp.PGPSecretKeyRing? = null

                override fun updatePeer(address: String, bytes: ByteArray, date: Long) {}
            }
        val tested =
            OpenPgpRequestHandler(fake, registrations, approvals) { mode, _, _, _ ->
                Intent().putExtra("mode", mode)
            }
        val result =
            tested.handle(
                request(ACTION_GET_KEY_IDS).putExtra(EXTRA_USER_IDS, arrayOf("victim@example.org")),
                null,
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals("recipient-picker", result.getStringExtra("mode"))
        val signed = ByteArrayOutputStream()
        Crypto.produce("signed message".byteInputStream(), signed, signer = key, cleartext = true)
        val verify =
            tested.handle(
                request(ACTION_DECRYPT_VERIFY).putExtra(EXTRA_SENDER_ADDRESS, "victim@example.org"),
                signed.toByteArray().inputStream(),
                ByteArrayOutputStream(),
                caller,
            )
        assertEquals(
            OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING,
            verify.getParcelableExtra<OpenPgpSignatureResult>(RESULT_SIGNATURE)!!.senderStatusResult,
        )
    }

    @Test
    fun registrationPermissionAndCertificateChange() {
        assertEquals(
            "register",
            call(request(ACTION_CHECK_PERMISSION)).first.getStringExtra("mode"),
        )
        registrations.register(caller)
        assertEquals(
            RESULT_CODE_SUCCESS,
            call(request(ACTION_CHECK_PERMISSION)).first.getIntExtra(RESULT_CODE, -1),
        )
        val changed =
            caller.copy(apps = listOf(caller.apps.single().copy(certificates = setOf("new-cert"))))
        val context =
            androidx.test.core.app.ApplicationProvider.getApplicationContext<
                android.content.Context
            >()
        val real = AppRegistrations(context)
        real.register(caller)
        assertTrue(real.registered(caller))
        assertFalse(real.registered(changed))
        real.revoke("test.app")
        assertFalse(real.registered(caller))
        assertEquals(
            RESULT_CODE_ERROR,
            call(request(ACTION_CHECK_PERMISSION).putExtra(EXTRA_API_VERSION, 99))
                .first
                .getIntExtra(RESULT_CODE, -1),
        )
    }

    @Test
    fun approvalsBoundSingleUseAndExpires() {
        val token = approvals.approve(caller, "sign", 7)
        assertFalse(approvals.consume(other, "sign", 7, null))
        assertFalse(approvals.consume(caller, "decrypt", 7, null))
        assertFalse(approvals.consume(caller, "sign", 8, null))
        assertTrue(approvals.consume(caller, "sign", 7, token))
        assertFalse(approvals.consume(caller, "sign", 7, token))
        approvals.approve(caller, "sign", 7)
        assertTrue(approvals.consume(caller, "sign", 7, null))
        assertFalse(approvals.consume(caller, "sign", 7, null))
        val expired = approvals.approve(caller, "sign", 7)
        now += 120_000
        assertFalse(approvals.consume(caller, "sign", 7, expired))
        approvals.approve(caller, "sign", 7, 300_000)
        assertTrue(approvals.consume(caller, "sign", 7, null))
        assertTrue(approvals.consume(caller, "sign", 7, null))
        approvals.clear()
        assertFalse(approvals.consume(caller, "sign", 7, null))
    }

    @Test
    fun publicOperationsWorkLockedAndSecretOperationsRequireApproval() {
        registrations.register(caller)
        assertEquals(
            RESULT_CODE_SUCCESS,
            call(request(ACTION_GET_KEY).putExtra(EXTRA_KEY_ID, indexed.id))
                .first
                .getIntExtra(RESULT_CODE, -1),
        )
        val ids =
            call(request(ACTION_GET_KEY_IDS).putExtra(EXTRA_USER_IDS, arrayOf("ed@example.org")))
                .first
        assertArrayEquals(longArrayOf(indexed.id), ids.getLongArrayExtra(RESULT_KEY_IDS))
        assertEquals(
            "sign-picker",
            call(request(ACTION_GET_SIGN_KEY_ID)).first.getStringExtra("mode"),
        )
        val signer =
            call(request(ACTION_GET_SIGN_KEY_ID).putExtra(EXTRA_SIGN_KEY_ID, indexed.id)).first
        assertEquals(indexed.id, signer.getLongExtra(EXTRA_SIGN_KEY_ID, 0))
        assertEquals(
            RESULT_CODE_ERROR,
            call(request(ACTION_GET_KEY).putExtra(EXTRA_KEY_ID, 4L))
                .first
                .getIntExtra(RESULT_CODE, -1),
        )
        assertEquals(
            RESULT_CODE_ERROR,
            call(request(ACTION_BACKUP)).first.getIntExtra(RESULT_CODE, -1),
        )
        assertEquals(RESULT_CODE_ERROR, call(request("unknown")).first.getIntExtra(RESULT_CODE, -1))
        val clear = "Hello Signet\n".toByteArray()
        val encryption =
            call(request(ACTION_ENCRYPT).putExtra(EXTRA_KEY_IDS, longArrayOf(indexed.id)), clear)
        assertEquals(RESULT_CODE_SUCCESS, encryption.first.getIntExtra(RESULT_CODE, -1))
        val decryptRequest = request(ACTION_DECRYPT_VERIFY)
        assertEquals(
            "approve",
            call(decryptRequest, encryption.second).first.getStringExtra("mode"),
        )
        backend.unlocked = true
        decryptRequest.putExtra(
            APPROVAL_TOKEN,
            approvals.approve(caller, ACTION_DECRYPT_VERIFY, indexed.id),
        )
        val decrypted = call(decryptRequest, encryption.second)
        assertArrayEquals(clear, decrypted.second)
        assertEquals(
            RESULT_CODE_USER_INTERACTION_REQUIRED,
            call(decryptRequest, encryption.second).first.getIntExtra(RESULT_CODE, -1),
        )
        for (action in
            listOf(
                ACTION_SIGN,
                ACTION_CLEARTEXT_SIGN,
                ACTION_DETACHED_SIGN,
                ACTION_SIGN_AND_ENCRYPT,
            )) {
            val sign =
                request(action)
                    .putExtra(EXTRA_SIGN_KEY_ID, indexed.id)
                    .putExtra(EXTRA_KEY_IDS, longArrayOf(indexed.id))
            assertEquals("approve", call(sign, clear).first.getStringExtra("mode"))
            sign.putExtra(APPROVAL_TOKEN, approvals.approve(caller, action, indexed.id))
            val result = call(sign, clear)
            assertEquals(
                "$action: ${result.first.getParcelableExtra<OpenPgpError>(RESULT_ERROR)?.message}",
                RESULT_CODE_SUCCESS,
                result.first.getIntExtra(RESULT_CODE, -1),
            )
            if (action == ACTION_DETACHED_SIGN)
                assertNotNull(result.first.getByteArrayExtra(RESULT_DETACHED_SIGNATURE))
            if (action == ACTION_CLEARTEXT_SIGN) {
                backend.unlocked = false
                val verify = call(request(ACTION_DECRYPT_VERIFY), result.second)
                assertEquals(
                    verify.first.getParcelableExtra<OpenPgpError>(RESULT_ERROR)?.message,
                    RESULT_CODE_SUCCESS,
                    verify.first.getIntExtra(RESULT_CODE, -1),
                )
                assertEquals(
                    OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
                    verify.first
                        .getParcelableExtra<OpenPgpSignatureResult>(RESULT_SIGNATURE)!!
                        .result,
                )
                backend.unlocked = true
            }
        }
        assertEquals(
            AUTOCRYPT_STATUS_AVAILABLE,
            call(
                    request(ACTION_QUERY_AUTOCRYPT_STATUS)
                        .putExtra(EXTRA_KEY_IDS, longArrayOf(indexed.id))
                )
                .first
                .getIntExtra(RESULT_AUTOCRYPT_STATUS, -1),
        )
        val update =
            AutocryptPeerUpdate.createAutocryptPeerUpdate(
                Crypto.publicPart(key).encoded,
                java.util.Date(),
            )
        assertEquals(
            RESULT_CODE_SUCCESS,
            call(
                    request(ACTION_UPDATE_AUTOCRYPT_PEER)
                        .putExtra(EXTRA_AUTOCRYPT_PEER_ID, "ed@example.org")
                        .putExtra(EXTRA_AUTOCRYPT_PEER_UPDATE, update)
                )
                .first
                .getIntExtra(RESULT_CODE, -1),
        )
    }

    @Test
    fun resultParcelRoundtrip() {
        registrations.register(caller)
        backend.unlocked = true
        val req =
            request(ACTION_DETACHED_SIGN)
                .putExtra(EXTRA_SIGN_KEY_ID, indexed.id)
                .putExtra(
                    APPROVAL_TOKEN,
                    approvals.approve(caller, ACTION_DETACHED_SIGN, indexed.id),
                )
        val result = call(req, "parcel".toByteArray()).first
        val parcel = Parcel.obtain()
        try {
            result.writeToParcel(parcel, 0)
            parcel.setDataPosition(0)
            val decoded = Intent.CREATOR.createFromParcel(parcel)
            assertArrayEquals(
                result.getByteArrayExtra(RESULT_DETACHED_SIGNATURE),
                decoded.getByteArrayExtra(RESULT_DETACHED_SIGNATURE),
            )
        } finally {
            parcel.recycle()
        }
        val metadata = OpenPgpMetadata("test.txt", "text/plain", 42, 200)
        val p = Parcel.obtain()
        try {
            metadata.writeToParcel(p, 0)
            p.setDataPosition(0)
            assertEquals("test.txt", OpenPgpMetadata.CREATOR.createFromParcel(p).filename)
        } finally {
            p.recycle()
        }
    }
}
