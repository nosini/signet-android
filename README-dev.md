# Android development

Use JDK 17, Android SDK platform 36, and NDK 27.0.12077973. Put `sdk.dir` in
an untracked `local.properties` if the SDK is not found automatically.

```sh
./gradlew --no-daemon assembleDebug lintDebug testDebugUnitTest
```

The debug APK is `app/build/outputs/apk/debug/app-debug.apk`. Install it on a
device using Android Studio or:

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
./gradlew connectedDebugAndroidTest
```

The instrumented tests check that stalled readers and writers reach their
pipe deadlines. Run them on Android 26 as well as a current Android version.

`vault/` holds the KeePass codec, pure merge and WebDAV implementation.
`crypto/` wraps PGPainless using lightweight Bouncy Castle cryptography,
independent of Android's platform BC provider. `api/` implements caller
certificate registration, approvals, persistent always-allow grants, PendingIntent screens, the plain
request handler, and both OpenPGP AIDL interfaces. `MainActivity` contains the
Compose UI. `Repository` serializes vault changes. Its idle timer runs independently
of sync, with at most one queued or running automatic sync worker. Unlock attempts
carry the cancellation epoch from the initiating action through publication. `SecureStore` and `Biometrics` use separate Android
Keystore
keys for WebDAV credentials and authenticated vault-password storage.

A small C helper sets pipe descriptors nonblocking on Android 26–29, where
`Os.fcntlInt` is not public. Kotlin's poll loops impose stream deadlines.
The helper builds for arm64, armv7, x86 and x86_64 with flexible page sizes.

JVM tests cover both key types, GnuPG vectors and verification of Signet
output by GnuPG when installed, provider registration, approval tokens and always-allow grants,
locked public operations, parcel formats, codec history and attachments,
Rust-produced KDBX files, merge, and WebDAV conditions and errors. They use
Robolectric and MockWebServer. The test resources include copies of the Linux
agent's missing-timestamp merge fixtures, so both codecs exercise the same inputs.
Device tests are needed for actual Keystore, biometric prompts, pipe timing, screen-off broadcasts and client-app flows.

Current dependencies are AGP 8.13.2, Gradle 8.14.2, Kotlin 2.3.21,
Compose BOM 2026.01.01, Activity 1.12.4, Navigation 2.9.7, Lifecycle 2.10.0,
Core 1.17.0, Biometric 1.1.0, coroutines 1.10.2, kotpass 0.13.0,
PGPainless 2.0.4 (Bouncy Castle 1.84), OkHttp 5.3.2, JUnit 4.13.2 and
Robolectric 4.16.1. AndroidX versions were selected to support compileSdk 36.
The complete declarations are in `gradle/libs.versions.toml`.

`openpgp-api/` vendors the Apache-2.0 client API with its original packages,
AIDL and parcel formats; see its LICENSE and NOTICE. Signet's provider is an
independent implementation. No Keyguard source is included.

## Continuous integration

`.github/workflows/android.yml` runs the build, lint and JVM tests above for
version tags and pull requests, and when started by hand from the Actions tab
or with `gh workflow run android.yml -R nosini/signet-android`. Pushes to
branches don't build. It uploads the debug APK as the `signet-debug`
artifact. Every CI run signs that APK with a new debug key, so Android will
not install a later build over it. The app must be uninstalled first, which
deletes its data.

For a release APK with a stable signature, generate a keystore on your own
machine, outside any source checkout, and store it in the repository's
secrets:

```sh
keytool -genkeypair -keystore signet-release.jks -alias signet \
  -keyalg EC -groupname secp256r1 -validity 10000 -dname CN=Signet
tmp=$(mktemp) && trap 'rm -f "$tmp"' EXIT
base64 -w0 signet-release.jks > "$tmp" && test -s "$tmp" &&
  gh secret set ANDROID_KEYSTORE_BASE64 -R nosini/signet-android < "$tmp"
gh secret set ANDROID_KEY_ALIAS -R nosini/signet-android --body signet
gh secret set ANDROID_KEYSTORE_PASSWORD -R nosini/signet-android
gh secret set ANDROID_KEY_PASSWORD -R nosini/signet-android
```

The last two commands prompt for a password. Enter the keystore password
`keytool` asked for at both prompts, because a PKCS12 keystore uses the same
password for the key.
With these secrets the workflow also uploads `signet-release`, an APK signed
by `apksigner`. Builds with this key can update each other. Keep a backup of
the keystore; losing it means users have to reinstall.

The workflow fails if the signed APK's certificate differs from
`CERT_SHA256`, the fingerprint published in README.md. Update both if the
release key ever changes.

## Releases

To publish a release, raise `versionCode` and set `versionName` in
`app/build.gradle.kts`, commit, then push a tag named after the version:

```sh
git tag -s v0.2.0 -m "Signet 0.2.0"
git push origin main v0.2.0
```

The workflow refuses a tag that differs from `versionName` or a build without
the signing secrets. It publishes `signet-0.2.0.apk` and its SHA-256 checksum
as a GitHub release whose notes include the certificate fingerprint. A tag
with a suffix, such as `v0.2.0-rc1`, becomes a prerelease. Android does not
install an update whose `versionCode` is lower than the installed one.
