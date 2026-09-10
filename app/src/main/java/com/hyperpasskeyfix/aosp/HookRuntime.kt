package com.hyperpasskeyfix.aosp

import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.error.HookFailedError
import org.luckypray.dexkit.DexKitBridge
import java.lang.reflect.Executable

internal const val MODULE_TAG = "HyperPasskeyFixAosp"

internal object TargetPackage {
    const val SETTINGS = "com.android.settings"
    const val PASSWORDS = "com.miui.passwords"
    const val FIDO = "com.fido.asm"
    const val CREDENTIAL_MANAGER = "com.android.credentialmanager"
    const val GMS = "com.google.android.gms"
}

/** Shared error handling and lazy DexKit loading for one target process. */
internal class HookRuntime(val xposed: XposedInterface) {
    fun hook(
        executable: Executable,
        priority: Int? = XposedInterface.PRIORITY_HIGHEST,
        exceptionMode: XposedInterface.ExceptionMode = XposedInterface.ExceptionMode.PROTECTIVE,
    ) = xposed.hook(executable).apply {
        priority?.let(::setPriority)
        setExceptionMode(exceptionMode)
    }

    fun attempt(label: String, action: () -> Unit): Boolean = try {
        action()
        true
    } catch (fatal: HookFailedError) {
        // libxposed documents this as a framework failure; do not hide it as a target mismatch.
        throw fatal
    } catch (t: Throwable) {
        xposed.log(Log.ERROR, MODULE_TAG, "$label: ${t.message}", t)
        false
    }

    fun warning(message: String, cause: Throwable? = null) {
        if (cause == null) {
            xposed.log(Log.WARN, MODULE_TAG, message)
        } else {
            xposed.log(Log.WARN, MODULE_TAG, message, cause)
        }
    }

    fun useDexKit(label: String, classLoader: ClassLoader, action: (DexKitBridge) -> Unit) {
        attempt(label) {
            DexKitNative.ensureLoaded()
            val bridge = DexKitBridge.create(classLoader, false)
            try {
                action(bridge)
            } finally {
                bridge.close()
            }
        }
    }
}

/** Loading here keeps native initialization after libxposed's onModuleLoaded lifecycle point. */
private object DexKitNative {
    @Volatile
    private var loaded = false

    fun ensureLoaded() {
        if (loaded) return
        synchronized(this) {
            if (!loaded) {
                System.loadLibrary("dexkit")
                loaded = true
            }
        }
    }
}
