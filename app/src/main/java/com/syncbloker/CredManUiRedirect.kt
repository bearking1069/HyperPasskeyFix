package com.syncbloker

import android.app.Activity
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.lang.reflect.ParameterizedType

/**
 * com.android.credentialmanager（小米凭据管理器前端，HyperOS 通行密钥/密码的保存与登录 UI）：
 *
 * 小米把 AOSP 上游的多提供方选择 UI 替换为固定确认对话框（“您要创建…通行密钥将存储在…中，
 * 且可在您所有的小米设备上使用。”），只能使用默认提供方（小米密码管家），用户无法选择
 * 保存/登录位置。而 AOSP 原生组件仍完整保留在同一 APK 中：
 *   - createflow.CreateCredentialComponentsKt（四态状态机：CreationSelectionCard /
 *     MoreOptionsSelectionCard / NonDefaultUsageConfirmationCard / ExternalOnlySelectionCard）
 *   - getflow.GetCredentialComponentsKt（PrimarySelectionCard / AllSignInOptionCard / 账户切换等）
 * 其全部 ViewModel 回调在小米改版的 CredentialSelectorViewModel 中原样健在，仅 UI 入口被
 * CredentialSelectorActivity 硬编码为 Mi 版。
 *
 * 两组入口函数签名完全一致：
 *   void X(CredentialSelectorViewModel, CreateCredentialUiState|GetCredentialUiState,
 *          ActivityResultLauncher, Composer, int)
 * 因此做“签名级重定向”：hook 小米入口函数，转发调用同 classloader 里的 AOSP 原版函数并跳过
 * 原方法。
 *
 * 主题适配（本模块修复的第二个问题）：
 * 小米重写的 com.android.compose.theme.PlatformTheme 只包 MaterialTheme，不再 provide AOSP
 * 组件依赖的 LocalAndroidColorScheme（AndroidColorSchemeKt.f10980a）；其默认工厂
 * （AndroidColorSchemeKt$LocalAndroidColorScheme$1.invoke）直接抛 IllegalStateException，
 * 导致 AOSP 界面在 ModalBottomSheet 处崩溃。更隐蔽的是，小米同时把该 scheme 的字段访问
 * 优化成了 getClass() + 0L：surface、文字和图标颜色因此全变成黑色，表现就是“按钮还在，
 * 文字和大部分内容消失”。所以除了补默认对象，还要在 Compose 的公共绘制入口恢复这些颜色。
 *
 * Compose 安全性：
 *   - 重定向完全接管（从不与原函数交错执行），composer 组嵌套干净；changed 位掩码因参数类型
 *     相同而语义等价；READY_TO_LAUNCH / PENDING / auto-select 分支两边实现相同。
 *   - 组合函数一旦开始消耗 Composer 就不可回退：若替换函数在组合中途抛异常，此时调用原方法
 *     会打破 start/end 平衡（ComposeRuntimeError）。因此重定向 hook 使用 PASSTHROUGH 异常模式，
 *     拦截器不做“失败回退 proceed”，让原始异常干净传播。
 */
internal class CredManUiRedirect(
    private val xposed: XposedInterface,
    private val logFn: (priority: Int, msg: String, t: Throwable?) -> Unit,
) {
    private fun log(priority: Int, msg: String) = logFn(priority, msg, null)

    private fun log(priority: Int, msg: String, t: Throwable?) = logFn(priority, msg, t)

    private var credentialActivity: Activity? = null

    fun hook(param: PackageReadyParam) {
        val cl = param.classLoader
        // 主题修复失败时 AOSP 界面必然在 LocalAndroidColorScheme 读取处抛 ISE，
        // 此时保持原 MI 对话框（不重定向），避免必崩。
        if (!hookColorSchemeDefault(cl)) {
            log(Log.WARN, "color scheme fix unavailable, keep original MI dialog (no redirect)")
            return
        }
        hookCredentialSelectorWindow(cl)
        hookAospColorLiterals(cl)
        hookAospLockedSingleEntryGet(cl)
        hookAospBottomSheetHideAnchorRace(cl)
        redirectScreen(
            cl, "create",
            MI_CREATE_CLASS, MI_CREATE_METHOD,
            AOSP_CREATE_CLASS, AOSP_CREATE_METHOD,
        )
        redirectScreen(
            cl, "get",
            MI_GET_CLASS, MI_GET_METHOD,
            AOSP_GET_CLASS, AOSP_GET_METHOD,
        )
    }

    /**
     * 小米的 CredentialSelectorActivity 使用了半透明、wrap-content 的窗口主题，但主题背景
     * 仍然是不透明的黑色。AOSP 的 ModalBottomSheet 只绘制底部 sheet，窗口上方本应透出
     * 被遮罩的调用方；黑色窗口背景会因此变成一整块空白黑色面板。
     *
     * 同时修复小米 AlertDialog.Theme 带来的系统栏副作用：该主题设置了 windowFullscreen=true，
     * 会隐藏状态栏；它还让内容停在导航栏上方，导致 BottomSheet 的背景无法沉到透明导航栏后面。
     * 这里恢复状态栏，保留系统导航按钮可见，并启用透明导航栏下的 edge-to-edge 布局。
     */
    private fun hookCredentialSelectorWindow(cl: ClassLoader) {
        val activityClass = loadClass(cl, CREDENTIAL_SELECTOR_ACTIVITY) ?: return
        val onCreate = try {
            activityClass.getDeclaredMethod("onCreate", Bundle::class.java).apply {
                isAccessible = true
            }
        } catch (t: Throwable) {
            log(Log.WARN, "CredentialSelectorActivity.onCreate not found: $t")
            return
        }

        xposed.hook(onCreate)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val activity = chain.thisObject as? Activity
                if (activity != null) {
                    credentialActivity = activity
                    makeCredentialWindowTransparent(activity)
                }
                val result = chain.proceed()
                if (activity != null) {
                    // setContent() 会在原 onCreate 中创建 DecorView，之后再清一次，
                    // 防止主题/Compose 宿主重新把背景设回不透明色。
                    makeCredentialWindowTransparent(activity)
                }
                result
            }
        log(Log.INFO, "hooked CredentialSelectorActivity window background")
    }

    private fun makeCredentialWindowTransparent(activity: Activity) {
        try {
            val window = activity.window
            window.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            window.clearFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN)
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION)
            window.statusBarColor = Color.TRANSPARENT
            window.navigationBarColor = Color.TRANSPARENT
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                window.navigationBarDividerColor = Color.TRANSPARENT
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }

            val decor = window.decorView
            decor.setBackgroundColor(Color.TRANSPARENT)
            var systemUi = decor.systemUiVisibility
            systemUi = systemUi and
                (View.SYSTEM_UI_FLAG_FULLSCREEN or
                    View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                    View.SYSTEM_UI_FLAG_IMMERSIVE or
                    View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
                    View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or
                    View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR).inv()
            // 只让内容铺到系统栏后面，不隐藏导航栏；深色界面使用白色系统图标。
            systemUi = systemUi or
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
            decor.systemUiVisibility = systemUi
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                window.setDecorFitsSystemWindows(false)
                window.insetsController?.setSystemBarsAppearance(
                    0,
                    WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                        WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                )
                window.insetsController?.show(
                    WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars()
                )
            }
            // 小米主题把这个 Activity 作为 wrapxwrap 浮动窗口创建，导致 AOSP
            // ModalBottomSheet 只能按 320dp 左右的窗口宽度计算。AOSP 选择器的
            // BoxWithConstraints 需要完整的应用区域，sheet 才能正确铺满可用宽度。
            window.setLayout(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
            )
        } catch (t: Throwable) {
            log(Log.WARN, "repair CredentialSelectorActivity window failed: $t")
        }
    }

    /**
     * 修复 AOSP 组件崩溃：LocalAndroidColorScheme 的默认工厂由抛异常改为返回 scheme 实例。
     * scheme 类型从工厂 lambda 的泛型接口签名动态推导，不硬编码混淆名。
     *
     * 注意：小米版把 scheme 类删成了无成员空类，且因全 APK 无任何实例化代码，R8 连默认
     * 构造器也一并移除（getDeclaredConstructor() 会 NoSuchMethod）——此时退回
     * Unsafe.allocateInstance 生成裸实例；全部消费点均为 getClass() 空读，裸实例即可。
     */
    private fun hookColorSchemeDefault(cl: ClassLoader): Boolean {
        val lambdaClass = try {
            Class.forName(LOCAL_COLOR_SCHEME_DEFAULT_LAMBDA, false, cl)
        } catch (t: Throwable) {
            log(Log.WARN, "color scheme default lambda not found: $LOCAL_COLOR_SCHEME_DEFAULT_LAMBDA")
            return false
        }
        val factory = lambdaClass.declaredMethods.firstOrNull {
            it.name == "invoke" && it.parameterCount == 0 && !Modifier.isStatic(it.modifiers)
        }
        if (factory == null) {
            log(Log.WARN, "color scheme default factory method not found")
            return false
        }
        val schemeClass = try {
            lambdaClass.genericInterfaces
                .filterIsInstance<ParameterizedType>()
                .flatMap { it.actualTypeArguments.toList() }
                .filterIsInstance<Class<*>>()
                .firstOrNull()
        } catch (t: Throwable) {
            null
        }
        if (schemeClass == null) {
            log(Log.WARN, "color scheme value type not resolvable from generic signature")
            return false
        }
        val maker = buildInstanceMaker(schemeClass)
        if (maker == null) {
            log(Log.WARN, "cannot instantiate scheme type: ${schemeClass.name}")
            return false
        }
        factory.isAccessible = true

        xposed.hook(factory)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { maker() }
        log(Log.INFO, "color scheme default factory hooked -> ${schemeClass.name}")
        return true
    }

    /** 优先默认构造器；被 R8 删除时退回 Unsafe.allocateInstance。 */
    private fun buildInstanceMaker(schemeClass: Class<*>): (() -> Any)? {
        val ctor = try {
            schemeClass.getDeclaredConstructor()
        } catch (t: Throwable) {
            null
        }
        if (ctor != null) {
            ctor.isAccessible = true
            return { ctor.newInstance() }
        }
        val allocate = acquireUnsafeAllocator() ?: return null
        return { allocate(schemeClass) }
    }

    /** sun.misc.Unsafe.allocateInstance：供被 R8 删除了默认构造器的类实例化。 */
    private fun acquireUnsafeAllocator(): ((Class<*>) -> Any)? {
        val unsafeClass = try {
            Class.forName("sun.misc.Unsafe")
        } catch (t: Throwable) {
            log(Log.WARN, "sun.misc.Unsafe unavailable: $t")
            return null
        }
        return try {
            val unsafe = unsafeClass.getDeclaredField("theUnsafe").apply { isAccessible = true }.get(null)
            val method = unsafeClass.getMethod("allocateInstance", Class::class.java)
            val fn: (Class<*>) -> Any = { p: Class<*> -> method.invoke(unsafe, p) as Any }
            fn
        } catch (t: Throwable) {
            log(Log.WARN, "Unsafe.allocateInstance unavailable: $t")
            null
        }
    }

    /**
     * 小米的 APK 中 AndroidColorScheme 类被 R8 缩成空类，原本的颜色属性访问点变成了 0L。
     * 0L 在 Compose Color 中是“不透明黑色”，不是 Color.Unspecified；因此必须在公共绘制点
     * 把这些常量替换成当前 Material3 ColorScheme 的值。这样不依赖小米的内部字段名，也能
     * 同时覆盖 create/get 两套 AOSP 组件。
     */
    private fun hookAospColorLiterals(cl: ClassLoader) {
        val theme = ComposeThemeAccess.create(cl)

        hookTextColorLiterals(cl, theme)
        hookIconColorLiterals(cl, theme)
        hookCardColorLiterals(cl, theme)
        hookBottomSheetColorLiteral(cl, theme)
    }

    /**
     * AOSP GetCredentialScreen 的单条锁定认证项兼容：
     *
     * 当 Bitwarden 是唯一返回来源且密码库锁定时，providerDisplayInfo 只有一个
     * AuthenticationEntryInfo，没有普通 CredentialEntryInfo。上游的
     * PrimarySelectionCard 仍把它当成普通单条凭据，先对空 CredentialType 调用
     * Intrinsics.checkNotNull，再把该空值传给 generateDisplayTitleTextResCode，最终
     * 在 Compose 测量阶段崩溃。存在第二个来源时 entry 数量不再是 1，所以不会触发。
     *
     * 不改变 provider 返回的 EntryInfo，只对这个已知调用栈放行空值检查，并让标题函数
     * 走它原本已经写好的“unlock options”分支。
     */
    private fun hookAospLockedSingleEntryGet(cl: ClassLoader) {
        val intrinsics = loadClass(cl, "kotlin.jvm.internal.p") ?: return
        val checkNotNull = intrinsics.declaredMethods.firstOrNull {
            it.name == "b" &&
                Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 1 &&
                it.parameterTypes[0] == Any::class.java &&
                it.returnType == Void.TYPE
        } ?: run {
            log(Log.WARN, "Kotlin Intrinsics.checkNotNull(Object) not found, locked get fix skipped")
            return
        }
        checkNotNull.isAccessible = true
        xposed.hook(checkNotNull)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                if (chain.getArg(0) == null && isLockedSingleEntryTitleCall()) {
                    null
                } else {
                    chain.proceed()
                }
            }

        val getModel = loadClass(cl, "com.android.credentialmanager.getflow.GetModelKt") ?: return
        val titleMethod = getModel.declaredMethods.firstOrNull {
            it.name == "generateDisplayTitleTextResCode" &&
                Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 2 &&
                it.returnType == Int::class.javaPrimitiveType &&
                List::class.java.isAssignableFrom(it.parameterTypes[1])
        } ?: run {
            log(Log.WARN, "GetModelKt.generateDisplayTitleTextResCode not found")
            return
        }
        val unlockOptionsTitle = stringResourceId(cl, "get_dialog_title_unlock_options_for")
        if (unlockOptionsTitle == null) {
            log(Log.WARN, "unlock-options title resource not found, locked get title fix skipped")
            return
        }
        titleMethod.isAccessible = true
        xposed.hook(titleMethod)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val authenticationEntries = chain.getArg(1) as? List<*>
                if (chain.getArg(0) == null && !authenticationEntries.isNullOrEmpty()) {
                    unlockOptionsTitle
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, "hooked AOSP locked single-entry get title compatibility")
    }

    private fun isLockedSingleEntryTitleCall(): Boolean =
        Throwable().stackTrace.any {
            it.className.contains(
                "GetCredentialComponentsKt\$PrimarySelectionCard\$1\$3"
            )
        }

    private fun stringResourceId(cl: ClassLoader, name: String): Int? = try {
        Class.forName("com.android.credentialmanager.R\$string", false, cl)
            .getDeclaredField(name)
            .apply { isAccessible = true }
            .getInt(null)
    } catch (t: Throwable) {
        log(Log.WARN, "string resource not found: $name")
        null
    }

    /**
     * AOSP BottomSheet 的 hide() 在状态重组时存在一个锚点竞态：
     *
     * ModalBottomSheetLayout 根据 sheet 高度重新生成 SwipeableState 的 anchors。锁定的
     * 单一 provider 在第一次返回结果时会触发一次快速重组，旧的 hide 协程可能在 anchors
     * 已更新、但 Hidden 锚点暂时还不存在时继续执行。SwipeableState.animateTo() 随后直接
     * 抛出 “The target value must have an associated anchor”，异常发生在主线程协程中，会
     * 把 CredentialSelectorActivity 一起打死。
     *
     * 空 anchors 仍交给原实现处理（它会等待 latestNonEmptyAnchorsFlow）；只有 anchors
     * 非空且明确缺少 Hidden 时拦截这次 hide，并结束已经失去有效状态的选择器 Activity。
     * 单纯跳过 hide 会留下全屏 scrim，单纯改 currentValue 又会绕过 AOSP 的 onDismiss
     * 回调，因此这里走和用户取消相同的最终结果：移除整个凭据窗口。
     */
    private fun hookAospBottomSheetHideAnchorRace(cl: ClassLoader) {
        val stateClass = loadClass(cl, "com.android.credentialmanager.common.material.ModalBottomSheetState")
            ?: return
        val hide = stateClass.declaredMethods.firstOrNull {
            it.name == "hide" &&
                !Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 1
        } ?: run {
            log(Log.WARN, "ModalBottomSheetState.hide not found, anchor race fix skipped")
            return
        }
        val anchorsGetter = stateClass.methods.firstOrNull {
            it.name == "getAnchors\$app_release" &&
                !Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 0
        } ?: run {
            log(Log.WARN, "SwipeableState anchors getter not found, anchor race fix skipped")
            return
        }
        val currentGetter = stateClass.methods.firstOrNull {
            it.name == "getCurrentValue" &&
                !Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 0
        } ?: run {
            log(Log.WARN, "SwipeableState current value getter not found, anchor race fix skipped")
            return
        }
        hide.isAccessible = true
        anchorsGetter.isAccessible = true
        currentGetter.isAccessible = true
        xposed.hook(hide)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val anchors = try {
                    anchorsGetter.invoke(chain.thisObject) as? Map<*, *>
                } catch (_: Throwable) {
                    null
                }
                val hasHiddenAnchor = anchors?.values?.any { it?.toString() == "Hidden" } == true
                if (!anchors.isNullOrEmpty() && !hasHiddenAnchor) {
                    val current = try {
                        currentGetter.invoke(chain.thisObject)?.toString()
                    } catch (_: Throwable) {
                        null
                    }
                    if (current != "Hidden") {
                        // 这里已经不是有效的 Compose 状态，继续保留窗口只会让 scrim
                        // 永久拦截触摸。直接结束选择器，等价于 AOSP 的 onDismiss 收尾。
                        credentialActivity?.let { activity ->
                            if (!activity.isFinishing) {
                                activity.finish()
                            }
                        }
                        log(Log.INFO, "finished CredentialSelectorActivity after missing Hidden anchor")
                    }
                    null
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, "hooked AOSP BottomSheet hide anchor race")
    }

    /** Texts.kt 的 LocalAndroidColorScheme.current.onSurface/onSurfaceVariant 被编成了 0L。 */
    private fun hookTextColorLiterals(cl: ClassLoader, theme: ComposeThemeAccess) {
        val textClass = loadClass(cl, "androidx.compose.material3.TextKt") ?: return
        val text = textClass.declaredMethods.firstOrNull {
            it.name == "b" &&
                Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.count { type -> type == Long::class.javaPrimitiveType } >= 3 &&
                it.parameterTypes.any { type -> type.name == "androidx.compose.runtime.f" }
        } ?: run {
            log(Log.WARN, "material3 TextKt.b not found, text color repair skipped")
            return
        }
        text.isAccessible = true
        xposed.hook(text)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val args = chain.args.toTypedArray()
                if (args[2] is Long && args[2] == 0L) {
                    args[2] = theme.color(args[17], "f5075p", "onSurface")
                    chain.proceed(args)
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, "hooked material3 TextKt.b zero-color repair")
    }

    /** Entry.kt 的 icon tint 也被压成 0L；恢复为 onSurfaceVariant。 */
    private fun hookIconColorLiterals(cl: ClassLoader, theme: ComposeThemeAccess) {
        val iconClass = loadClass(cl, "androidx.compose.material3.IconKt") ?: return
        var count = 0
        for (name in arrayOf("a", "b", "c")) {
            val icon = iconClass.declaredMethods.firstOrNull {
                it.name == name && it.parameterCount == 7 && Modifier.isStatic(it.modifiers)
            } ?: continue
            icon.isAccessible = true
            xposed.hook(icon)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { chain ->
                    val args = chain.args.toTypedArray()
                    if (args[3] is Long && args[3] == 0L) {
                        args[3] = theme.color(args[4], "f5079r", "onSurfaceVariant")
                        chain.proceed(args)
                    } else {
                        chain.proceed()
                    }
                }
            count++
        }
        if (count > 0) log(Log.INFO, "hooked material3 IconKt zero-tint repair ($count overloads)")
    }

    /** Cards.kt 的 CardDefaults.containerColor 被压成 0L，恢复 surfaceBright。 */
    private fun hookCardColorLiterals(cl: ClassLoader, theme: ComposeThemeAccess) {
        val helperClass = loadClass(cl, "e0.c") ?: return
        val cardColors = helperClass.declaredMethods.firstOrNull {
            it.name == "D" && it.parameterCount == 3 && Modifier.isStatic(it.modifiers)
        } ?: run {
            log(Log.WARN, "e0.c.D not found, card color repair skipped")
            return
        }
        cardColors.isAccessible = true
        xposed.hook(cardColors)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val args = chain.args.toTypedArray()
                if (args[0] is Long && args[0] == 0L) {
                    args[0] = theme.color(args[1], "C", "surfaceBright")
                    chain.proceed(args)
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, "hooked e0.c.D zero-color card repair")
    }

    /** BottomSheet.kt 的 sheetBackgroundColor 被压成 0L，恢复 surfaceBright。 */
    private fun hookBottomSheetColorLiteral(cl: ClassLoader, theme: ComposeThemeAccess) {
        val sheetClass = loadClass(cl, "com.android.credentialmanager.common.material.ModalBottomSheetKt")
            ?: return
        val layout = sheetClass.declaredMethods.firstOrNull {
            it.name == "m20ModalBottomSheetLayoutXBZIF8" &&
                Modifier.isStatic(it.modifiers) &&
                it.returnType == Void.TYPE &&
                it.parameterTypes.count { type -> type == Long::class.javaPrimitiveType } >= 2 &&
                it.parameterTypes.any { type -> type.name == "androidx.compose.runtime.f" }
        } ?: run {
            log(Log.WARN, "ModalBottomSheetLayout not found, sheet color repair skipped")
            return
        }
        layout.isAccessible = true
        xposed.hook(layout)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val args = chain.args.toTypedArray()
                val colorIndex = args.indexOfFirst { it is Long && it == 0L }
                val composerIndex = args.indexOfFirst { it?.javaClass?.name == "androidx.compose.runtime.ComposerImpl" }
                if (colorIndex >= 0 && composerIndex >= 0) {
                    args[colorIndex] = theme.color(args[composerIndex], "C", "surfaceBright")
                    chain.proceed(args)
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, "hooked ModalBottomSheetLayout zero-color repair")
    }

    private fun loadClass(cl: ClassLoader, name: String): Class<*>? = try {
        Class.forName(name, false, cl)
    } catch (t: Throwable) {
        log(Log.WARN, "class not found: $name")
        null
    }

    /** Reflection bridge for the target APK's obfuscated-but-stable Material3 ColorScheme fields. */
    private class ComposeThemeAccess private constructor(
        private val localColorScheme: Any?,
        private val composerRead: Method?,
        private val fallbackColors: Map<String, Long>,
    ) {
        fun color(composer: Any?, fieldName: String, role: String): Long {
            try {
                if (composerRead == null || localColorScheme == null || composer == null) {
                    return fallbackColors[role] ?: 0L
                }
                val scheme = composerRead.invoke(composer, localColorScheme) ?: return fallbackColors[role] ?: 0L
                val field = scheme.javaClass.getDeclaredField(fieldName).apply { isAccessible = true }
                val value = field.getLong(scheme)
                return if (value != 0L) value else fallbackColors[role] ?: 0L
            } catch (_: Throwable) {
                return fallbackColors[role] ?: 0L
            }
        }

        companion object {
            fun create(cl: ClassLoader): ComposeThemeAccess {
                var fallbackColors = mapOf(
                    "onSurface" to (-1L shl 32),
                    "onSurfaceVariant" to (0xffcac4d0L shl 32),
                    "surfaceBright" to (0xff2b2930L shl 32),
                )
                var local: Any? = null
                var read: Method? = null
                try {
                    val composerClass = Class.forName("androidx.compose.runtime.ComposerImpl", false, cl)
                    val schemeKt = Class.forName("androidx.compose.material3.ColorSchemeKt", false, cl)
                    local = schemeKt.getDeclaredField("f4259a").apply { isAccessible = true }.get(null)
                    read = composerClass.methods.firstOrNull {
                        it.name == "J" && it.parameterCount == 1
                    } ?: composerClass.declaredMethods.firstOrNull {
                        it.name == "J" && it.parameterCount == 1
                    }
                    read?.isAccessible = true
                    fallbackColors = mapOf(
                        "onSurface" to (-1L shl 32),
                        "onSurfaceVariant" to (0xffcac4d0L shl 32),
                        "surfaceBright" to (0xff2b2930L shl 32),
                    )
                } catch (_: Throwable) {
                    // Xiaomi's split/optimized class loader can make one of the optional
                    // reflection lookups unavailable. The literal repair must still be
                    // installed with stable dark Material3 fallback colors.
                }
                return ComposeThemeAccess(local, read, fallbackColors)
            }
        }
    }

    private fun redirectScreen(
        cl: ClassLoader,
        label: String,
        originClass: String,
        originMethod: String,
        replacementClass: String,
        replacementMethod: String,
    ) {
        val origin = findScreenMethod(cl, originClass, originMethod)
        if (origin == null) {
            log(Log.WARN, "[$label] origin not found: $originClass.$originMethod, skip")
            return
        }
        val replacement = findScreenMethod(cl, replacementClass, replacementMethod)
        if (replacement == null) {
            log(Log.WARN, "[$label] AOSP replacement not found: $replacementClass.$replacementMethod, skip")
            return
        }
        origin.isAccessible = true
        replacement.isAccessible = true

        xposed.hook(origin)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PASSTHROUGH)
            .intercept { chain ->
                try {
                    replacement.invoke(null, *chain.args.toTypedArray())
                    null
                } catch (t: Throwable) {
                    // 组合已开始，不可回退原方法；记录后让异常干净传播
                    log(Log.WARN, "[$label] redirect failed: $t", t)
                    throw t
                }
            }
        log(
            Log.INFO,
            "[$label] redirected ${origin.declaringClass.name}.${origin.name}" +
                " -> ${replacement.declaringClass.name}.${replacement.name}"
        )
    }

    /** 定位 Compose 编译器生成的入口函数：静态、void、5 参（ViewModel/UiState/Launcher/Composer/int）。 */
    private fun findScreenMethod(cl: ClassLoader, className: String, methodName: String): Method? {
        val clazz = try {
            Class.forName(className, false, cl)
        } catch (t: Throwable) {
            log(Log.WARN, "class not found: $className")
            return null
        }
        return clazz.declaredMethods.firstOrNull {
            it.name == methodName &&
                Modifier.isStatic(it.modifiers) &&
                it.parameterCount == 5 &&
                it.returnType == Void.TYPE
        }
    }

    private companion object {
        const val CREDENTIAL_SELECTOR_ACTIVITY =
            "com.android.credentialmanager.CredentialSelectorActivity"
        const val MI_CREATE_CLASS = "com.android.credentialmanager.createflow.CreateMiCredentialComponentsKt"
        const val MI_CREATE_METHOD = "CreateMiCredentialScreen"
        const val AOSP_CREATE_CLASS = "com.android.credentialmanager.createflow.CreateCredentialComponentsKt"
        const val AOSP_CREATE_METHOD = "CreateCredentialScreen"

        const val MI_GET_CLASS = "com.android.credentialmanager.getflow.GetMiCredentialComponentsKt"
        const val MI_GET_METHOD = "GetMiCredentialScreen"
        const val AOSP_GET_CLASS = "com.android.credentialmanager.getflow.GetCredentialComponentsKt"
        const val AOSP_GET_METHOD = "GetCredentialScreen"

        const val LOCAL_COLOR_SCHEME_DEFAULT_LAMBDA =
            "com.android.compose.theme.AndroidColorSchemeKt\$LocalAndroidColorScheme\$1"
    }
}
