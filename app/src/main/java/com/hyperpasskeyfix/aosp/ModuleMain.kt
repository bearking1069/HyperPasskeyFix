package com.hyperpasskeyfix.aosp

import android.os.Build
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam

/** Modern libxposed API 101 entry point. */
class ModuleMain : XposedModule() {
    override fun onPackageReady(param: PackageReadyParam) {
        // A scoped process can load code from additional packages. Install only for its owner.
        if (!param.isFirstPackage) return

        val runtime = HookRuntime(this)
        when (param.packageName) {
            TargetPackage.SETTINGS -> if (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
            ) {
                runtime.useDexKit(
                    "initialize Xiaomi credential-provider settings hooks",
                    param.classLoader,
                ) { bridge ->
                    ProviderSettingsHooks(runtime).install(param, bridge)
                }
            }

            TargetPackage.PASSWORDS -> runtime.useDexKit(
                "initialize optional Xiaomi password-manager hooks",
                param.classLoader,
            ) { bridge ->
                SyncValidationHooks(runtime).installForPasswords(param, bridge)
            }

            TargetPackage.FIDO -> runtime.useDexKit(
                "initialize Xiaomi FIDO hooks",
                param.classLoader,
            ) { bridge ->
                SyncValidationHooks(runtime).installForFido(param, bridge)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    HybridPasskeyHooks(runtime).installForFido(param, bridge)
                }
            }

            TargetPackage.CREDENTIAL_MANAGER -> runtime.useDexKit(
                "initialize AOSP credential selector hooks",
                param.classLoader,
            ) { bridge ->
                LocalPasskeyHooks(runtime).install(param, bridge)
            }

            // Optional scope: needed only when Google Password Manager must trust Hybrid requests.
            TargetPackage.GMS -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                HybridPasskeyHooks(runtime).installForGoogleProvider(param)
            }
        }
    }
}
