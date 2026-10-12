# Signet

Signet keeps OpenPGP keys in an encrypted KeePass vault and asks before
signing or decrypting. This is the Android app: an OpenKeychain-compatible
OpenPGP provider. Signet for Linux, a GnuPG-compatible agent, is a separate
project; both can sync the same KDBX file over WebDAV.

The name comes from a signet ring: a seal used to sign documents. The code is
licensed under **GPL-3.0-or-later**. The application ID is `eu.nosini.signet`.

## Installation and use

Download `signet-VERSION.apk` from the
[releases page](https://github.com/nosini/signet-android/releases) and open it
on your phone; Android asks you to allow installing apps from your browser or
file manager. Signet needs Android 8.0 or later. Apps such as Obtainium can
install new releases from that page as they appear. To build the APK
yourself, see [README-dev.md](README-dev.md).

Open Signet. Create a new vault, open an existing KDBX file, or connect to
the WebDAV URL of an existing vault. If Signet for Linux already created your
vault, start from that same file.

Unlock the vault to import or generate keys. Ed25519/X25519 is the default;
RSA 4096 is also available. Public certificates remain available while
locked. Secret-key export requires confirmation and rechecking the vault credentials.
For a keyfile-only vault, that check uses the stored key file and an empty
password; it does not prove the user's presence. Use a master password when
export reauthentication is important.
Settings include idle locking, screen-off locking, biometric unlock, sync,
and connected-app revocation.

Apps that work with OpenKeychain can use Signet instead: mail apps such as
Thunderbird for Android, FairEmail and Sterna Mail, and Password Store
(1.13, its last release). In the app's settings, choose **Signet** as the
OpenPGP provider. The first request
asks you to register the application, showing its package and signing
certificate. Each signing or decryption request asks for approval. The
approval screen can unlock the vault and offers optional reuse for five
minutes or until the vault locks. The default is to ask every time.

The approval screen can also always allow an app to decrypt, or to sign,
with a particular key. Signet then stops asking for approval, even after the
vault locks; it still asks you to unlock the vault, or to enter a key's own
passphrase, when the key isn't available. Android identifies the app by its
package and signing certificate, which other apps can't forge, but anything
running inside that app can then use the key without you seeing it, including
an update from its developer. Decryption and signing are allowed separately,
and you can stop either under Settings, Connected apps. Revoking the app or
registering it again after its certificate changes removes these grants.

The provider implements OpenPGP API versions 7–12, including the progress
reports version 12 adds. Public-key encryption and
signature verification work while locked. Autocrypt peer keys are stored
locally, scoped to the calling app and the address they arrived for, and kept
separate from vault contacts. Its Autocrypt status reports
key availability; mutual-preference negotiation and gossip processing are
not implemented. Keyserver lookup and provider backup are unsupported.

Android builds and JVM tests do not replace device testing. Biometric unlock,
Binder pipe deadlines, and the complete flows in client applications should
be checked on a device before using Signet for important keys.

## Verifying the APK

Signet APKs are signed with this certificate:

```
eu.nosini.signet
AD:CD:17:F7:74:62:35:D5:78:E4:2B:90:95:50:92:6B:8F:9A:C9:BE:7B:3A:AD:E1:98:3B:BC:FF:55:B0:3F:44
```

To check an APK before installing it, run
`apksigner verify --print-certs signet-release.apk`. The
`certificate SHA-256 digest` it prints is the same value in lowercase,
without colons. After installing, you can share the two lines above to
[AppVerifier](https://github.com/soupslurpr/AppVerifier), which compares them
with the installed app. Android only installs an update signed with the same
certificate as the installed app, so a mismatch also shows up as a failed
update.

## WebDAV and storage

Use the HTTPS URL of a `.kdbx` file with **Connect WebDAV** when setting up a
vault. Signet stores WebDAV credentials using Android Keystore and uses Basic
authentication over HTTPS.

Sync runs while unlocked, after local changes, and on request. ETags protect
conditional uploads. Concurrent edits merge by UUID, retaining history and
attachments; the previous five local files are kept as backups. Servers
without ETags have weaker protection against simultaneous uploads.
[docs/vault-format.md](docs/vault-format.md) describes the file format and
merge rules, including unsupported XML extensions. Every device sharing the
vault must use the same vault password and key file.

The server receives only the encrypted vault. Signet has no analytics or
keyserver traffic. Android system backup is disabled. Public-key indexes,
key fingerprints, app registrations and always-allow grants remain in private local storage while
locked. Locking drops decrypted vault and key references; Android's managed
runtime controls when that memory is reclaimed. Importing a key removes its
OpenPGP passphrase, so protect your vault password and backups accordingly.

The key-entry field names match Keyguard's KeePass format. Signet does not
contain Keyguard source code. Third-party notices are in
[openpgp-api/NOTICE](openpgp-api/NOTICE).
