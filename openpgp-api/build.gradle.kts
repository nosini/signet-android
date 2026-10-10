plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.openintents.openpgp"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
    }

    buildFeatures {
        aidl = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        // Vendored third-party code, kept byte-identical to upstream.
        abortOnError = false
    }
}
