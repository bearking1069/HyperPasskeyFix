package com.hyperpasskeyfix.aosp

import android.annotation.SuppressLint
import android.app.Activity
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.luckypray.dexkit.DexKitBridge
import java.lang.ref.WeakReference
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType

/** Restores the AOSP create/get selector retained inside Xiaomi's CredentialManager APK. */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi", "InlinedApi")
internal class LocalPasskeyHooks(private val runtime: HookRuntime) {
    private val xposed = runtime.xposed
    @Volatile
    private var activityReference = WeakReference<Activity>(null)
    @Volatile
    private var cachedPalette: CachedPalette? = null

    fun install(param: PackageReadyParam, bridge: DexKitBridge) {
        val classLoader = param.classLoader
        var needsLiteralColorRepair = false
        val schemeHookInstalled = runtime.attempt("AOSP AndroidColorScheme compatibility") {
            needsLiteralColorRepair = installAndroidColorSchemeDefault(bridge, classLoader)
        }
        if (!schemeHookInstalled) return

        runtime.attempt("CredentialSelectorActivity window") {
            hookCredentialSelectorWindow(classLoader)
        }
        if (needsLiteralColorRepair) {
            val colorHooksInstalled = runtime.attempt("AOSP selector colors") {
                hookAospColorLiterals(bridge, classLoader)
            }
            if (!colorHooksInstalled) return
        }
        runtime.attempt("AOSP locked-provider compatibility") {
            hookLockedSingleProvider(bridge, classLoader)
        }
        runtime.attempt("AOSP bottom-sheet dismissal") {
            hookBottomSheetAnchorRace(classLoader)
        }
        runtime.attempt("AOSP create selector redirect") {
            redirectScreen(
                classLoader,
                MI_CREATE_CLASS,
                MI_CREATE_METHOD,
                AOSP_CREATE_CLASS,
                AOSP_CREATE_METHOD,
            )
        }
        runtime.attempt("AOSP get selector redirect") {
            redirectScreen(
                classLoader,
                MI_GET_CLASS,
                MI_GET_METHOD,
                AOSP_GET_CLASS,
                AOSP_GET_METHOD,
            )
        }
    }

    /**
     * Xiaomi removed the provider for LocalAndroidColorScheme and its generated default throws.
     * The exception text is stable source content, so locate the factory by DexKit instead of its
     * generated lambda class name. If the marker is absent, that target version does not need this fix.
     */
    private fun installAndroidColorSchemeDefault(
        bridge: DexKitBridge,
        classLoader: ClassLoader,
    ): Boolean {
        val factoryData = bridge.findMethod {
            findFirst = true
            searchPackages("com.android.compose.theme")
            matcher {
                paramCount = 0
                usingStrings(COLOR_SCHEME_ERROR)
            }
        }.singleOrNull() ?: return false
        val factory = factoryData.getMethodInstance(classLoader).apply { isAccessible = true }
        val schemeType = factory.returnType.takeUnless { it == Any::class.java }
            ?: resolveGenericFactoryType(factory.declaringClass)
            ?: error("AndroidColorScheme result type not found")
        val instanceMaker = buildInstanceMaker(schemeType)
            ?: error("AndroidColorScheme cannot be instantiated")

        runtime.hook(factory)
            .intercept { instanceMaker() }
        return true
    }

    private fun resolveGenericFactoryType(factoryClass: Class<*>): Class<*>? = runCatching {
        factoryClass.genericInterfaces
            .filterIsInstance<ParameterizedType>()
            .flatMap { it.actualTypeArguments.asSequence() }
            .filterIsInstance<Class<*>>()
            .firstOrNull()
    }.getOrNull()

    private fun buildInstanceMaker(type: Class<*>): (() -> Any)? {
        runCatching { type.getDeclaredConstructor() }.getOrNull()?.let { constructor ->
            constructor.isAccessible = true
            return { constructor.newInstance() }
        }
        return acquireUnsafeAllocator()?.let { allocate -> { allocate(type) } }
    }

    private fun acquireUnsafeAllocator(): ((Class<*>) -> Any)? = runCatching {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafe = unsafeClass.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
        val allocate = unsafeClass.getMethod("allocateInstance", Class::class.java)
        val allocator: (Class<*>) -> Any = { type -> allocate.invoke(unsafe, type) as Any }
        allocator
    }.getOrNull()

    private fun hookCredentialSelectorWindow(classLoader: ClassLoader) {
        val activityClass = Class.forName(CREDENTIAL_SELECTOR_ACTIVITY, false, classLoader)
        val onCreate = activityClass.getDeclaredMethod("onCreate", Bundle::class.java)
            .apply { isAccessible = true }

        runtime.hook(onCreate)
            .intercept { chain ->
                val activity = chain.thisObject as? Activity
                if (activity != null) {
                    activityReference = WeakReference(activity)
                    repairWindow(activity)
                }
                val result = chain.proceed()
                activity?.let(::repairWindow)
                result
            }
    }

    @Suppress("DEPRECATION")
    private fun repairWindow(activity: Activity) {
        val window = activity.window
        val lightBars = activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK !=
            Configuration.UI_MODE_NIGHT_YES

        window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
        window.clearFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN)
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION)
        window.statusBarColor = Color.TRANSPARENT
        // AOSP keeps both bars transparent while the sheet is hidden. Its composable switches the
        // navigation bar to the sheet color as soon as the sheet starts expanding.
        window.navigationBarColor = Color.TRANSPARENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            window.navigationBarDividerColor = Color.TRANSPARENT
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        val decor = window.decorView
        decor.setBackgroundColor(Color.TRANSPARENT)
        val visibilityMask = View.SYSTEM_UI_FLAG_FULLSCREEN or
            View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
            View.SYSTEM_UI_FLAG_IMMERSIVE or
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
            View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or
            View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        var visibility = decor.systemUiVisibility and visibilityMask.inv()
        visibility = visibility or View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
            View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
            View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        if (lightBars) {
            visibility = visibility or View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
            visibility = visibility or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        }
        decor.systemUiVisibility = visibility

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            val lightAppearance = if (lightBars) {
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            } else {
                0
            }
            window.insetsController?.setSystemBarsAppearance(
                lightAppearance,
                WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
            )
            window.insetsController?.show(
                WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars(),
            )
        }
        window.setLayout(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
        )
    }

    private fun hookAospColorLiterals(bridge: DexKitBridge, classLoader: ClassLoader) {
        hookTextColors(classLoader)
        hookIconColors(classLoader)
        hookCardColors(bridge, classLoader)
        hookBottomSheetColor(classLoader)
    }

    /** Finds the String Text overload by its shape, not its R8 method name. */
    private fun hookTextColors(classLoader: ClassLoader) {
        val methods = Class.forName(MATERIAL_TEXT_CLASS, false, classLoader).declaredMethods.filter {
            Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.firstOrNull() == String::class.java &&
                it.parameterTypes.count { type -> type == Long::class.javaPrimitiveType } >= 3 &&
                it.parameterTypes.any(::isComposerType)
        }
        if (methods.isEmpty()) error("Material3 String Text overload not found")
        methods.forEach { method -> hookColorLiteral(method) { palette().onSurface } }
    }

    /** All three Icon overloads have the same seven-parameter shape. */
    private fun hookIconColors(classLoader: ClassLoader) {
        val methods = Class.forName(MATERIAL_ICON_CLASS, false, classLoader).declaredMethods.filter {
            Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterCount == 7 &&
                it.parameterTypes.getOrNull(1) == String::class.java &&
                it.parameterTypes.count { type -> type == Long::class.javaPrimitiveType } == 1 &&
                it.parameterTypes.any(::isComposerType)
        }
        if (methods.isEmpty()) error("Material3 Icon overloads not found")
        methods.forEach { method -> hookColorLiteral(method) { palette().onSurfaceVariant } }
    }

    /** Resolves the R8-moved CardDefaults factory from the CardColors type and method prototype. */
    private fun hookCardColors(bridge: DexKitBridge, classLoader: ClassLoader) {
        val cardClass = Class.forName(MATERIAL_CARD_CLASS, false, classLoader)
        val cardMethod = cardClass.declaredMethods.firstOrNull {
            Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.any(::isComposerType) &&
                it.parameterTypes.any(::looksLikeCardColors)
        } ?: error("Material3 Card composable not found")
        val colorType = cardMethod.parameterTypes.first(::looksLikeCardColors)
        val composerType = cardMethod.parameterTypes.first(::isComposerType)
        val factory = bridge.findMethod {
            findFirst = true
            matcher {
                modifiers = Modifier.STATIC
                returnType = colorType.name
                paramTypes("long", composerType.name, "int")
            }
        }.singleOrNull()?.getMethodInstance(classLoader)
            ?: error("Material3 CardColors factory not found")
        hookColorLiteral(factory) { palette().surfaceBright }
    }

    private fun looksLikeCardColors(type: Class<*>): Boolean =
        type.name.startsWith("androidx.compose.material3.") &&
            type.declaredFields.count {
                !Modifier.isStatic(it.modifiers) && it.type == Long::class.javaPrimitiveType
            } == 4

    /** Locates ModalBottomSheetLayout by parameter structure, independent of JVM mangling. */
    private fun hookBottomSheetColor(classLoader: ClassLoader) {
        val stateClass = Class.forName(BOTTOM_SHEET_STATE_CLASS, false, classLoader)
        val sheetClass = Class.forName(BOTTOM_SHEET_CLASS, false, classLoader)
        val layout = sheetClass.declaredMethods.firstOrNull {
            Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.any { type -> type == stateClass } &&
                it.parameterTypes.count { type -> type == Long::class.javaPrimitiveType } >= 2 &&
                it.parameterTypes.any(::isComposerType)
        } ?: error("AOSP ModalBottomSheetLayout not found")
        hookColorLiteral(layout) { palette().surfaceBright }
    }

    private fun hookColorLiteral(method: Method, replacement: () -> Long) {
        val colorIndex = method.parameterTypes.indexOfFirst { it == Long::class.javaPrimitiveType }
        require(colorIndex >= 0) { "color parameter not found in ${method.name}" }
        method.isAccessible = true
        runtime.hook(method).intercept { chain ->
            val args = chain.args.toTypedArray()
            if (args[colorIndex] == 0L) {
                args[colorIndex] = replacement()
                chain.proceed(args)
            } else {
                chain.proceed()
            }
        }
    }

    private fun isComposerType(type: Class<*>): Boolean =
        type.name.startsWith("androidx.compose.runtime.") && !type.isPrimitive

    private fun palette(): ComposePalette {
        val activity = activityReference.get() ?: return LIGHT_PALETTE
        val nightMode = activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK
        cachedPalette?.takeIf { it.nightMode == nightMode }?.let { return it.colors }

        val dark = nightMode == Configuration.UI_MODE_NIGHT_YES
        val fallback = if (dark) DARK_PALETTE else LIGHT_PALETTE
        val resources = if (dark) DARK_COLOR_RESOURCES else LIGHT_COLOR_RESOURCES
        val colors = ComposePalette(
            onSurface = activity.systemComposeColor(resources.onSurface, fallback.onSurface),
            onSurfaceVariant = activity.systemComposeColor(
                resources.onSurfaceVariant,
                fallback.onSurfaceVariant,
            ),
            surfaceBright = activity.systemComposeColor(
                resources.surfaceBright,
                fallback.surfaceBright,
            ),
        )
        cachedPalette = CachedPalette(nightMode, colors)
        return colors
    }

    private fun Activity.systemComposeColor(id: Int, fallback: Long): Long =
        runCatching { color(resources.getColor(id, theme).toLong()) }.getOrDefault(fallback)

    /**
     * A lone locked provider reaches PrimarySelectionCard with a null CredentialType. Its headline
     * is a lazy item, so it can run after PrimarySelectionCard itself has returned. Match that lazy
     * call only when the null is observed, then use AOSP's existing "unlock options" title.
     */
    private fun hookLockedSingleProvider(bridge: DexKitBridge, classLoader: ClassLoader) {
        val intrinsicsClass = bridge.findClass {
            findFirst = true
            searchPackages("kotlin.jvm.internal")
            matcher { usingStrings("Parameter specified as non-null is null: method ") }
        }.singleOrNull()?.getInstance(classLoader)
            ?: error("Kotlin Intrinsics class not found")
        val checkNotNull = intrinsicsClass.declaredMethods.firstOrNull {
            Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.contentEquals(arrayOf(Any::class.java))
        } ?: error("Kotlin checkNotNull(Object) not found")
        val titleMethod = Class.forName(GET_MODEL_CLASS, false, classLoader)
            .declaredMethods.firstOrNull {
                it.name == DISPLAY_TITLE_METHOD &&
                    Modifier.isStatic(it.modifiers) &&
                    it.returnType == Int::class.javaPrimitiveType &&
                    it.parameterCount == 2 &&
                    java.util.List::class.java.isAssignableFrom(it.parameterTypes[1])
            } ?: error("AOSP display-title method not found")
        val unlockOptionsTitle = Class.forName(CREDENTIAL_MANAGER_STRING_CLASS, false, classLoader)
            .getDeclaredField(UNLOCK_OPTIONS_TITLE)
            .apply { isAccessible = true }
            .getInt(null)

        checkNotNull.isAccessible = true
        titleMethod.isAccessible = true
        runtime.hook(checkNotNull)
            .intercept { chain ->
                if (chain.getArg(0) == null && isLockedProviderHeadlineCall()) {
                    null
                } else {
                    chain.proceed()
                }
            }
        runtime.hook(titleMethod)
            .intercept { chain ->
                val authenticationEntries = chain.getArg(1) as? List<*>
                if (
                    chain.getArg(0) == null &&
                    !authenticationEntries.isNullOrEmpty() &&
                    isLockedProviderHeadlineCall()
                ) {
                    unlockOptionsTitle
                } else {
                    chain.proceed()
                }
            }
    }

    private fun isLockedProviderHeadlineCall(): Boolean = Throwable().stackTrace.any { frame ->
        frame.className.startsWith("$AOSP_GET_CLASS\$PrimarySelectionCard\$")
    }

    /** Finish only when the bottom sheet tries to animate to a missing anchor. */
    private fun hookBottomSheetAnchorRace(classLoader: ClassLoader) {
        val stateClass = Class.forName(BOTTOM_SHEET_STATE_CLASS, false, classLoader)
        val hide = stateClass.declaredMethods.firstOrNull {
            it.name == "hide" && !Modifier.isStatic(it.modifiers) && it.parameterCount == 1
        } ?: error("ModalBottomSheetState.hide not found")

        hide.isAccessible = true
        runtime.hook(hide, exceptionMode = XposedInterface.ExceptionMode.PASSTHROUGH)
            .intercept { chain ->
                try {
                    chain.proceed()
                } catch (failure: Throwable) {
                    if (!isMissingAnchorFailure(failure)) throw failure
                    activityReference.get()
                        ?.takeUnless { it.isFinishing || it.isDestroyed }
                        ?.finish()
                    null
                }
            }
    }

    private fun isMissingAnchorFailure(failure: Throwable): Boolean =
        generateSequence(failure) { it.cause }.any {
            it.message?.contains(MISSING_ANCHOR_ERROR, ignoreCase = true) == true
        }

    private fun redirectScreen(
        classLoader: ClassLoader,
        sourceClass: String,
        sourceMethod: String,
        targetClass: String,
        targetMethod: String,
    ) {
        val source = findScreenMethod(classLoader, sourceClass, sourceMethod)
            ?: error("source screen not found: $sourceClass.$sourceMethod")
        val target = findScreenMethod(classLoader, targetClass, targetMethod)
            ?: error("AOSP screen not found: $targetClass.$targetMethod")
        if (!source.parameterTypes.contentEquals(target.parameterTypes)) {
            error("selector screen signatures differ")
        }
        val targetInvoker = xposed.getInvoker(target)

        runtime.hook(source, exceptionMode = XposedInterface.ExceptionMode.PASSTHROUGH)
            .intercept { chain ->
                targetInvoker.invoke(null, *chain.args.toTypedArray())
                null
            }
    }

    private fun findScreenMethod(
        classLoader: ClassLoader,
        className: String,
        methodName: String,
    ): Method? = runCatching {
        Class.forName(className, false, classLoader).declaredMethods.firstOrNull {
            it.name == methodName &&
                Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterCount == 5
        }
    }.getOrNull()

    private data class ComposePalette(
        val onSurface: Long,
        val onSurfaceVariant: Long,
        val surfaceBright: Long,
    )

    private data class CachedPalette(val nightMode: Int, val colors: ComposePalette)

    private data class ComposeColorResources(
        val onSurface: Int,
        val onSurfaceVariant: Int,
        val surfaceBright: Int,
    )

    private companion object {
        const val CREDENTIAL_SELECTOR_ACTIVITY =
            "com.android.credentialmanager.CredentialSelectorActivity"
        const val MI_CREATE_CLASS =
            "com.android.credentialmanager.createflow.CreateMiCredentialComponentsKt"
        const val MI_CREATE_METHOD = "CreateMiCredentialScreen"
        const val AOSP_CREATE_CLASS =
            "com.android.credentialmanager.createflow.CreateCredentialComponentsKt"
        const val AOSP_CREATE_METHOD = "CreateCredentialScreen"
        const val MI_GET_CLASS =
            "com.android.credentialmanager.getflow.GetMiCredentialComponentsKt"
        const val MI_GET_METHOD = "GetMiCredentialScreen"
        const val AOSP_GET_CLASS =
            "com.android.credentialmanager.getflow.GetCredentialComponentsKt"
        const val AOSP_GET_METHOD = "GetCredentialScreen"
        const val GET_MODEL_CLASS = "com.android.credentialmanager.getflow.GetModelKt"
        const val DISPLAY_TITLE_METHOD = "generateDisplayTitleTextResCode"
        const val CREDENTIAL_MANAGER_STRING_CLASS = "com.android.credentialmanager.R\$string"
        const val UNLOCK_OPTIONS_TITLE = "get_dialog_title_unlock_options_for"
        const val MATERIAL_TEXT_CLASS = "androidx.compose.material3.TextKt"
        const val MATERIAL_ICON_CLASS = "androidx.compose.material3.IconKt"
        const val MATERIAL_CARD_CLASS = "androidx.compose.material3.CardKt"
        const val BOTTOM_SHEET_CLASS =
            "com.android.credentialmanager.common.material.ModalBottomSheetKt"
        const val BOTTOM_SHEET_STATE_CLASS =
            "com.android.credentialmanager.common.material.ModalBottomSheetState"
        const val MISSING_ANCHOR_ERROR = "target value must have an associated anchor"
        const val COLOR_SCHEME_ERROR =
            "No AndroidColorScheme configured. Make sure to use LocalAndroidColorScheme in a Composable surrounded by a PlatformTheme {}."

        fun color(argb: Long): Long = (argb and 0xffffffffL) shl 32

        val LIGHT_PALETTE = ComposePalette(
            onSurface = color(0xff1d1b20L),
            onSurfaceVariant = color(0xff49454fL),
            surfaceBright = color(0xfffff7ffL),
        )
        val DARK_PALETTE = ComposePalette(
            onSurface = color(0xffe6e0e9L),
            onSurfaceVariant = color(0xffcac4d0L),
            surfaceBright = color(0xff3b383eL),
        )
        val LIGHT_COLOR_RESOURCES = ComposeColorResources(
            onSurface = android.R.color.system_on_surface_light,
            onSurfaceVariant = android.R.color.system_on_surface_variant_light,
            surfaceBright = android.R.color.system_surface_bright_light,
        )
        val DARK_COLOR_RESOURCES = ComposeColorResources(
            onSurface = android.R.color.system_on_surface_dark,
            onSurfaceVariant = android.R.color.system_on_surface_variant_dark,
            surfaceBright = android.R.color.system_surface_bright_dark,
        )
    }
}
