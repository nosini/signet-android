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
certificate registration, approvals, PendingIntent screens, the plain
request handler, and both OpenPGP AIDL interfaces. `MainActivity` contains the
Compose UI. `Repository` serializes vault changes and runs idle locking and
periodic sync. `SecureStore` and `Biometrics` use separate Android Keystore
keys for WebDAV credentials and authenticated vault-password storage.

A small C helper sets pipe descriptors nonblocking on Android 26–29, where
`Os.fcntlInt` is not public. Kotlin's poll loops impose stream deadlines.
The helper builds for arm64, armv7, x86 and x86_64 with flexible page sizes.

JVM tests cover both key types, GnuPG vectors and verification of Signet
output by GnuPG when installed, provider registration and approval tokens,
locked public operations, parcel formats, codec history and attachments,
Rust-produced KDBX files, merge, and WebDAV conditions and errors. They use
Robolectric and MockWebServer. Device tests are needed for actual Keystore,
biometric prompts, pipe timing, screen-off broadcasts and client-app flows.

Current dependencies are AGP 8.13.2, Gradle 8.14.2, Kotlin 2.3.21,
Compose BOM 2026.01.01, Activity 1.12.4, Navigation 2.9.7, Lifecycle 2.10.0,
Core 1.17.0, Biometric 1.1.0, coroutines 1.10.2, kotpass 0.13.0,
PGPainless 2.0.4 (Bouncy Castle 1.84), OkHttp 5.3.2, JUnit 4.13.2 and
Robolectric 4.16.1. AndroidX versions were selected to support compileSdk 36.
The complete declarations are in `gradle/libs.versions.toml`.

`openpgp-api/` vendors the Apache-2.0 client API with its original packages,
AIDL and parcel formats; see its LICENSE and NOTICE. Signet's provider is an
independent implementation. No Keyguard source is included.
