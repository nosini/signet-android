# Signet

Signet keeps OpenPGP keys in an encrypted KeePass vault and asks before
signing or decrypting. This is the Android app: an OpenKeychain-compatible
OpenPGP provider. Signet for Linux, a GnuPG-compatible agent, is a separate
project; both can sync the same KDBX file over WebDAV.

The name comes from a signet ring: a seal used to sign documents. The code is
licensed under **GPL-3.0-or-later**. The application ID is `eu.nosini.signet`.

## Installation and use

Build the APK using [README-dev.md](README-dev.md), install it,
and open Signet. Create a new vault, open an existing KDBX file, or connect to
the WebDAV URL of an existing vault. If Signet for Linux already created your
vault, start from that same file.

Unlock the vault to import or generate keys. Ed25519/X25519 is the default;
RSA 4096 is also available. Public certificates remain available while
locked. Secret-key export requires confirmation and the vault password.
Settings include idle locking, screen-off locking, biometric unlock, sync,
and connected-app revocation.

In a compatible application such as Thunderbird for Android, FairEmail, or
Password Store, choose **Signet** as the OpenPGP provider. The first request
asks you to register the application, showing its package and signing
certificate. Each signing or decryption request asks for approval. The
approval screen can unlock the vault and offers optional reuse for five
minutes or until the vault locks. The default is to ask every time.

The provider implements OpenPGP API versions 7–11. Public-key encryption and
signature verification work while locked. Autocrypt peer keys are stored
locally, scoped to the calling app and the address they arrived for, and kept
separate from vault contacts. Its Autocrypt status reports
key availability; mutual-preference negotiation and gossip processing are
not implemented. Keyserver lookup and provider backup are unsupported.

Android builds and JVM tests do not replace device testing. Biometric unlock,
Binder pipe deadlines, and the complete flows in client applications should
be checked on a device before using Signet for important keys.

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
key fingerprints and app registrations remain in private local storage while
locked. Locking drops decrypted vault and key references; Android's managed
runtime controls when that memory is reclaimed. Importing a key removes its
OpenPGP passphrase, so protect your vault password and backups accordingly.

The key-entry field names match Keyguard's KeePass format. Signet does not
contain Keyguard source code. Third-party notices are in
[openpgp-api/NOTICE](openpgp-api/NOTICE).
