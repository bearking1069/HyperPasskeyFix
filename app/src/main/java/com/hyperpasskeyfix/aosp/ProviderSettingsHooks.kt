/*
 * Portions of this file are adapted from Howard20181/HyperPasskey.
 * Copyright (C) Howard20181
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
package com.hyperpasskeyfix.aosp

import android.annotation.SuppressLint
import android.graphics.Point
import android.os.Build
import android.view.View
import android.widget.CompoundButton
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.luckypray.dexkit.DexKitBridge
import org.luckypray.dexkit.query.FindMethod
import org.luckypray.dexkit.query.matchers.MethodMatcher
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.concurrent.locks.ReentrantLock

/**
 * Restores third-party credential-provider controls hidden by China-build Settings.
 *
 * This is the Settings-only portion adapted from Howard20181/HyperPasskey. The Xiaomi build flag
 * is changed only while the relevant Settings method is on the current thread and is restored in
 * a finally block; SecurityCenter's default-setting writers are intentionally left untouched.
 */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi", "SoonBlockedPrivateApi")
internal class ProviderSettingsHooks(private val runtime: HookRuntime) {
    private val xposed = runtime.xposed

    fun install(param: PackageReadyParam, bridge: DexKitBridge) {
        val classLoader = param.classLoader
        val internationalBuild = runCatching {
            Class.forName(MIUI_BUILD_CLASS, false, classLoader)
                .getDeclaredField(INTERNATIONAL_BUILD_FIELD)
                .apply { isAccessible = true }
        }.getOrElse {
            runtime.warning("MIUI international-build flag not found; Settings hooks skipped", it)
            return
        }
        val guard = InternationalBuildGuard(internationalBuild, StaticBooleanWriter(runtime))

        runtime.attempt("Settings combined-provider picker") {
            hookWithInternationalBuild(
                declaredMethod(
                    classLoader,
                    DEFAULT_COMBINED_PICKER,
                    "setDefaultKey",
                    String::class.java,
                ),
                guard,
            )
        }
        runtime.attempt("Settings combined-provider summary") {
            hookWithInternationalBuild(
                declaredMethod(
                    classLoader,
                    DEFAULT_COMBINED_PREFERENCE_CONTROLLER,
                    "getCombinedProviderInfos",
                    Class.forName(CREDENTIAL_MANAGER_CLASS, false, classLoader),
                    Int::class.javaPrimitiveType!!,
                ),
                guard,
            )
        }
        runtime.attempt("Settings provider details click") {
            hookProviderDetailsClicks(classLoader, bridge, guard)
        }

        if (Build.VERSION.SDK_INT == ANDROID_14_API) {
            runtime.attempt("Android 14 default-provider preference") {
                hookWithInternationalBuild(
                    declaredMethod(
                        classLoader,
                        DEFAULT_APP_PREFERENCE_CONTROLLER,
                        "updateState",
                        Class.forName(PREFERENCE_CLASS, false, classLoader),
                    ),
                    guard,
                )
            }
        }

        if (Build.VERSION.SDK_INT >= ANDROID_17_API) {
            runtime.attempt("Android 17 credential-provider switches") {
                hookAndroid17SwitchBinding(classLoader, bridge)
            }
        }
    }

    private fun hookProviderDetailsClicks(
        classLoader: ClassLoader,
        bridge: DexKitBridge,
        guard: InternationalBuildGuard,
    ) {
        val launchBoolean = MethodMatcher.create().addInvoke(PROVIDER_SETTINGS_LAUNCH_BOOLEAN)
        val launchVoid = MethodMatcher.create().addInvoke(PROVIDER_SETTINGS_LAUNCH_VOID)
        val matches = bridge.findMethod(
            FindMethod.create()
                .searchPackages(CREDENTIAL_SETTINGS_PACKAGE)
                .matcher(
                    MethodMatcher.create()
                        .name("onLeftSideClicked")
                        .paramCount(0)
                        .anyOf(launchBoolean, launchVoid),
                ),
        )

        val methods = matches.mapNotNull { data ->
            runCatching { data.getMethodInstance(classLoader) }.getOrNull()
        }.distinctBy(Method::toGenericString)
        check(methods.isNotEmpty()) { "provider details click handler not found" }
        methods.forEach { hookWithInternationalBuild(it, guard) }
    }

    private fun hookWithInternationalBuild(method: Method, guard: InternationalBuildGuard) {
        method.isAccessible = true
        xposed.deoptimize(method)
        runtime.hook(method)
            .intercept { chain -> guard.run { chain.proceed() } }
    }

    /** Android 17 moved switch wiring out of CombiPreference; restore the AOSP listener binding. */
    private fun hookAndroid17SwitchBinding(classLoader: ClassLoader, bridge: DexKitBridge) {
        val combiPreference = Class.forName(COMBI_PREFERENCE_CLASS, false, classLoader)
        val preferenceViewHolder = Class.forName(PREFERENCE_VIEW_HOLDER_CLASS, false, classLoader)
        val onBindViewHolder = declaredMethod(
            classLoader,
            COMBI_PREFERENCE_CLASS,
            "onBindViewHolder",
            preferenceViewHolder,
        )
        val checkedField = combiPreference.getDeclaredField("mChecked").accessible()
        val clickListenerField = combiPreference.getDeclaredField("mOnClickListener").accessible()
        val switchField = combiPreference.getDeclaredField("mSwitch").accessible()
        val updateDescription = combiPreference.getDeclaredMethod("maybeUpdateContentDescription")
            .apply { isAccessible = true }

        val recyclerViewHolder = Class.forName(RECYCLER_VIEW_HOLDER_CLASS, false, classLoader)
        val itemViewField = recyclerViewHolder.getField("itemView")
        val settingsLibIds = Class.forName(SETTINGS_LIB_ID_CLASS, false, classLoader)
        val switchWidgetId = settingsLibIds.getDeclaredField("switchWidget")
            .apply { isAccessible = true }
            .getInt(null)

        val enabledCall = MethodMatcher.create().addInvoke(TOGGLE_PROVIDER_ENABLED)
        val disabledCall = MethodMatcher.create().addInvoke(TOGGLE_PROVIDER_DISABLED)
        val onCheckChanged = bridge.findMethod(
            FindMethod.create()
                .searchPackages(CREDENTIAL_SETTINGS_PACKAGE)
                .matcher(
                    MethodMatcher.create()
                        .name("onCheckChanged")
                        .paramTypes(combiPreference, Boolean::class.javaPrimitiveType!!)
                        .anyOf(enabledCall, disabledCall),
                ),
        ).mapNotNull { data ->
            runCatching { data.getMethodInstance(classLoader) }.getOrNull()
        }.firstOrNull { it.returnType == Boolean::class.javaPrimitiveType }
            ?: error("credential-provider switch callback not found")
        onCheckChanged.isAccessible = true

        onBindViewHolder.isAccessible = true
        runtime.hook(onBindViewHolder, priority = null)
            .intercept { chain ->
                val result = chain.proceed()
                val preference = chain.thisObject ?: return@intercept result
                if (switchField.get(preference) != null) return@intercept result

                val holder = chain.getArg(0) ?: return@intercept result
                val itemView = itemViewField.get(holder) as? View ?: return@intercept result
                val switchView = itemView.findViewById<View>(switchWidgetId) as? CompoundButton
                    ?: return@intercept result

                switchView.isChecked = checkedField.getBoolean(preference)
                switchView.setOnClickListener {
                    val listener = clickListenerField.get(preference) ?: return@setOnClickListener
                    val callback = if (onCheckChanged.declaringClass.isInstance(listener)) {
                        onCheckChanged
                    } else {
                        listener.javaClass.getDeclaredMethod(
                            onCheckChanged.name,
                            *onCheckChanged.parameterTypes,
                        ).apply { isAccessible = true }
                    }
                    val accepted = xposed.getInvoker(callback)
                        .invoke(listener, preference, switchView.isChecked) as? Boolean ?: false
                    if (!accepted) {
                        checkedField.setBoolean(preference, false)
                        switchView.isChecked = false
                    }
                }
                switchField.set(preference, switchView)
                xposed.getInvoker(updateDescription).invoke(preference)
                result
            }
    }

    private fun declaredMethod(
        classLoader: ClassLoader,
        className: String,
        methodName: String,
        vararg parameterTypes: Class<*>,
    ): Method = Class.forName(className, false, classLoader)
        .getDeclaredMethod(methodName, *parameterTypes)

    private fun Field.accessible(): Field = apply { isAccessible = true }

    private class InternationalBuildGuard(
        private val field: Field,
        private val writer: StaticBooleanWriter,
    ) {
        private val lock = ReentrantLock(true)
        private val depth = ThreadLocal<Int>()
        private val previousValue = ThreadLocal<Boolean>()

        fun run(block: () -> Any?): Any? {
            lock.lock()
            var entered = false
            try {
                val currentDepth = depth.get() ?: 0
                if (currentDepth == 0) {
                    val previous = field.getBoolean(null)
                    previousValue.set(previous)
                    if (!previous && !writer.set(field, true)) {
                        previousValue.remove()
                        return block()
                    }
                }
                depth.set(currentDepth + 1)
                entered = true
                return block()
            } finally {
                if (entered) {
                    val remainingDepth = (depth.get() ?: 1) - 1
                    if (remainingDepth == 0) {
                        val previous = previousValue.get()
                        depth.remove()
                        previousValue.remove()
                        if (previous != null) writer.set(field, previous)
                    } else {
                        depth.set(remainingDepth)
                    }
                }
                lock.unlock()
            }
        }
    }

    /** Writes a static-final ART field without keeping the MIUI flag globally modified. */
    private class StaticBooleanWriter(private val runtime: HookRuntime) {
        private val unsafe by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            val unsafeClass = Class.forName("sun.misc.Unsafe")
            val instance = unsafeClass.getDeclaredField("theUnsafe")
                .apply { isAccessible = true }
                .get(null) ?: error("sun.misc.Unsafe singleton is null")
            UnsafeAccess(unsafeClass, instance)
        }
        private val fieldOffsetOffset by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            findFieldOffsetOffset()
        }

        fun set(field: Field, value: Boolean): Boolean {
            val result = runCatching {
                if (!requiresUnsafe(field)) {
                    runCatching {
                        field.isAccessible = true
                        field.setBoolean(null, value)
                    }.getOrElse {
                        writeWithUnsafe(field, value)
                    }
                } else {
                    writeWithUnsafe(field, value)
                }
            }
            result.exceptionOrNull()?.let {
                runtime.warning("Unable to update MIUI international-build flag", it)
            }
            return result.isSuccess
        }

        private fun requiresUnsafe(field: Field): Boolean {
            val staticFinal = Modifier.STATIC or Modifier.FINAL
            val restrictedRuntime = Build.VERSION.SDK_INT >= ANDROID_17_API ||
                (Build.VERSION.SDK_INT == ANDROID_16_API && Build.VERSION.PREVIEW_SDK_INT > 0)
            return restrictedRuntime && (field.modifiers and staticFinal) == staticFinal
        }

        private fun writeWithUnsafe(field: Field, value: Boolean) {
            runCatching {
                field.isAccessible = true
                field.get(null)
            }
            val targetOffset = unsafe.getInt(field, fieldOffsetOffset).toLong()
            unsafe.putBoolean(field.declaringClass, targetOffset, value)
        }

        private fun findFieldOffsetOffset(): Long {
            runCatching {
                val offsetField = Field::class.java.getDeclaredField("offset")
                    .apply { isAccessible = true }
                offsetField.getInt(offsetField)
                return unsafe.objectFieldOffset(offsetField)
            }

            val probeField = Point::class.java.getDeclaredField("x")
            val probe = Point()
            probeField.getInt(probe)
            val actualFieldOffset = unsafe.objectFieldOffset(probeField).toInt()
            for (candidate in 8 until 256 step 4) {
                val candidateOffset = candidate.toLong()
                if (unsafe.getInt(probeField, candidateOffset) != actualFieldOffset) continue

                val modifiedOffset = actualFieldOffset.inv()
                unsafe.putInt(probeField, candidateOffset, modifiedOffset)
                val observedOffset = unsafe.objectFieldOffset(probeField).toInt()
                unsafe.putInt(probeField, candidateOffset, actualFieldOffset)
                if (observedOffset == modifiedOffset) return candidateOffset
            }
            error("ART Field offset slot not found")
        }
    }

    private class UnsafeAccess(type: Class<*>, private val instance: Any) {
        private val getInt = type.getMethod(
            "getInt",
            Any::class.java,
            Long::class.javaPrimitiveType,
        )
        private val putInt = type.getMethod(
            "putInt",
            Any::class.java,
            Long::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
        )
        private val putBoolean = type.getMethod(
            "putBoolean",
            Any::class.java,
            Long::class.javaPrimitiveType,
            Boolean::class.javaPrimitiveType,
        )
        private val objectFieldOffset = type.getMethod("objectFieldOffset", Field::class.java)

        fun getInt(target: Any, offset: Long): Int = getInt.invoke(instance, target, offset) as Int

        fun putInt(target: Any, offset: Long, value: Int) {
            putInt.invoke(instance, target, offset, value)
        }

        fun putBoolean(target: Any, offset: Long, value: Boolean) {
            putBoolean.invoke(instance, target, offset, value)
        }

        fun objectFieldOffset(field: Field): Long =
            objectFieldOffset.invoke(instance, field) as Long
    }

    private companion object {
        const val ANDROID_14_API = 34
        const val ANDROID_16_API = 36
        const val ANDROID_17_API = 37

        const val MIUI_BUILD_CLASS = "miui.os.Build"
        const val INTERNATIONAL_BUILD_FIELD = "IS_INTERNATIONAL_BUILD"
        const val CREDENTIAL_MANAGER_CLASS = "android.credentials.CredentialManager"
        const val CREDENTIAL_SETTINGS_PACKAGE = "com.android.settings.applications.credentials"
        const val DEFAULT_COMBINED_PICKER =
            "$CREDENTIAL_SETTINGS_PACKAGE.DefaultCombinedPicker"
        const val DEFAULT_COMBINED_PREFERENCE_CONTROLLER =
            "$CREDENTIAL_SETTINGS_PACKAGE.DefaultCombinedPreferenceController"
        const val COMBI_PREFERENCE_CLASS =
            "$CREDENTIAL_SETTINGS_PACKAGE.CredentialManagerPreferenceController\$CombiPreference"
        const val DEFAULT_APP_PREFERENCE_CONTROLLER =
            "com.android.settings.applications.defaultapps.DefaultAppPreferenceController"
        const val PREFERENCE_CLASS = "androidx.preference.Preference"
        const val PREFERENCE_VIEW_HOLDER_CLASS = "androidx.preference.PreferenceViewHolder"
        const val RECYCLER_VIEW_HOLDER_CLASS = "androidx.recyclerview.widget.RecyclerView\$ViewHolder"
        const val SETTINGS_LIB_ID_CLASS = "com.android.settingslib.R\$id"

        const val PROVIDER_SETTINGS_LAUNCH_BOOLEAN =
            "Lcom/android/settings/applications/credentials/CombinedProviderInfo;->" +
                "launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;" +
                "Ljava/lang/CharSequence;I)Z"
        const val PROVIDER_SETTINGS_LAUNCH_VOID =
            "Lcom/android/settings/applications/credentials/CombinedProviderInfo;->" +
                "launchSettingsActivityIntent(Landroid/content/Context;Ljava/lang/CharSequence;" +
                "Ljava/lang/CharSequence;I)V"
        const val TOGGLE_PROVIDER_ENABLED =
            "Lcom/android/settings/applications/credentials/CredentialManagerPreferenceController;->" +
                "togglePackageNameEnabled(Ljava/lang/String;)Z"
        const val TOGGLE_PROVIDER_DISABLED =
            "Lcom/android/settings/applications/credentials/CredentialManagerPreferenceController;->" +
                "togglePackageNameDisabled(Ljava/lang/String;)V"
    }
}
