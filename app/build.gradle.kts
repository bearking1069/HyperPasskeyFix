plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.hyperpasskeyfix.aosp"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.hyperpasskeyfix.aosp"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = false
    }

    packaging {
        resources {
            merges += "META-INF/xposed/*"
            excludes += "**"
        }
    }

    lint {
        // This module deliberately ships only for the arm64 Xiaomi target device family.
        disable += "ChromeOsAbiSupport"
    }
}

dependencies {
    compileOnly(libs.libxposed.api)
    implementation(libs.dexkit)
}
