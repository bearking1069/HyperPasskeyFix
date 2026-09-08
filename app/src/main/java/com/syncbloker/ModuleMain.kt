package com.syncbloker

import android.accounts.Account
import android.app.Activity
import android.content.ContentResolver
import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.luckypray.dexkit.DexKitBridge
import java.lang.reflect.Modifier

/**
 * LSPosed (API 101) 模块。
 *
 * 1. com.miui.passwords（密码管理）：
 *    a) 让 CredentialSupportHelper.getSyncEnable() 恒返回 true，绕过
 *       “请先开启密码管家，再使用通行密钥”的前置校验。
 *    b) 清除“全部通行密钥”列表 exchangeStatus=0 过滤（只显示已同步记录）：
 *       数据适配器 DATA_MANAGERSecurityStorageAdapter 的查询方法去掉 SQL 里的
 *       exchangeStatus 条件；游标→模型工厂把 exchangeStatus 归零（覆盖 Java 二次过滤）。
 *    —— 均通过 DexKit 按字节码特征（日志/列名字符串）定位混淆类/方法，跨版本无需映射表。
 *
 * 2. com.fido.asm（FIDO 引擎）：
 *    a) hook 框架 API ContentResolver.getSyncAutomatically，authority 为 "miui.autofill" 时恒真，
 *       覆盖其同步状态校验（CredentialOperationBaseActivity / QRAuthenticatorActivity / TeeTransport）。
 *    b) 旧 UAF 白名单：NokNok FacetIDsValidator 从 SharedPreferences("gmrzList"/"whiteList")
 *       拉取包名白名单（isAppTrust / isFacetIdInList 恒真）。
 *    c) FIDO2 的 VendorValidator（混淆类 p2.e）：底层 vendor 校验不通过时抛
 *       “vendor validate failed : message=…。serialNo=…”（如 browser not allow）。
 *       用 DexKit 按特征字符串 "vendor validate failed" 定位并 no-op 掉整个校验。
 */
class ModuleMain : XposedModule() {

    companion object {
        private const val TAG = "SyncBloker"
        private const val TARGET_PACKAGE_PASSWORDS = "com.miui.passwords"
        private const val TARGET_PACKAGE_FIDO = "com.fido.asm"
        private const val SYNC_AUTHORITY = "miui.autofill"
        private const val FACET_ID_VALIDATOR = "com.noknok.android.uaf.framework.service.FacetIDsValidator"
    }

    private val hookedPackages = mutableSetOf<String>()

    init {
        System.loadLibrary("dexkit")
    }

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        log(Log.INFO, TAG, "module loaded, apiVersion=$apiVersion")
    }

    override fun onPackageReady(param: PackageReadyParam) {
        val pkg = param.packageName
        if (pkg !in setOf(TARGET_PACKAGE_PASSWORDS, TARGET_PACKAGE_FIDO)) return
        if (!hookedPackages.add(pkg)) return

        try {
            when (pkg) {
                TARGET_PACKAGE_PASSWORDS -> {
                    hookSyncEnablePasswords(param)
                    hookPasskeyExchangeStatusFilter(param)
                }
                TARGET_PACKAGE_FIDO -> {
                    hookSyncEnableFido()
                    hookNokNokWhitelist(param)
                    hookFidoVendorValidate(param)
                }
            }
            log(Log.INFO, TAG, "hooks installed for $pkg")
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "hook failed for $pkg: ${t.message}", t)
        }
    }

    /** com.miui.passwords：让 getSyncEnable 恒真（DexKit 按字节码特征定位混淆方法）。 */
    private fun hookSyncEnablePasswords(param: PackageReadyParam) {
        val bridge = DexKitBridge.create(param.classLoader, false)
        try {
            val methodData = findMethodByMarker(bridge, "boolean", 0, "get sync enable").firstOrNull()
                ?: findMethodByMarker(bridge, "boolean", 0, "CredentialSupportHelper").firstOrNull()
                ?: throw IllegalStateException("getSyncEnable method not found")

            val method = methodData.getMethodInstance(param.classLoader)
            hook(method)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { true }

            log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name}")
        } finally {
            bridge.close()
        }
    }

    /** com.miui.passwords：清除“全部通行密钥”列表的 exchangeStatus=0 过滤（只显示已同步记录）。 */
    private fun hookPasskeyExchangeStatusFilter(param: PackageReadyParam) {
        val bridge = DexKitBridge.create(param.classLoader, false)
        try {
            // exchangeStatus 设值方法 k(long)，其声明类即通行密钥模型类
            val setter = bridge.findMethod {
                matcher {
                    returnType = "void"
                    paramTypes("long")
                    usingStrings("exchangeStatus")
                }
            }.firstOrNull()?.getMethodInstance(param.classLoader)
                ?: throw IllegalStateException("exchangeStatus setter not found")
            val modelClass = setter.declaringClass

            // 数据适配器查询方法 e(Class,String,String[])：去掉 SQL 里的 exchangeStatus 条件
            bridge.findMethod {
                matcher {
                    paramCount = 3
                    usingStrings("Query failed: ")
                }
            }.forEach { md ->
                val method = md.getMethodInstance(param.classLoader)
                hook(method)
                    .setPriority(XposedInterface.PRIORITY_HIGHEST)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept { chain ->
                        val cls = chain.getArg(0)
                        val selection = chain.getArg(1) as? String
                        if (cls == modelClass && selection?.contains("exchangeStatus") == true) {
                            val args = chain.getArg(2) as? Array<String?>
                            val (newSel, newArgs) = stripExchangeStatus(selection, args)
                            chain.proceed(arrayOf(cls, newSel, newArgs))
                        } else {
                            chain.proceed()
                        }
                    }
                log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name} (passkey query)")
            }

            // 游标→模型工厂 j(Cursor,Class)：新建的通行密钥记录 exchangeStatus 归零（覆盖 Java 过滤）
            bridge.findMethod {
                matcher {
                    paramCount = 2
                    usingStrings("Unsupported model: ")
                }
            }.forEach { md ->
                val method = md.getMethodInstance(param.classLoader)
                hook(method)
                    .setPriority(XposedInterface.PRIORITY_HIGHEST)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept { chain ->
                        val obj = chain.proceed()
                        if (modelClass.isInstance(obj)) {
                            setter.invoke(obj, 0L)
                        }
                        obj
                    }
                log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name} (passkey factory)")
            }
        } finally {
            bridge.close()
        }
    }

    /** 去掉 SQL selection 里的 "exchangeStatus = ?" 条件及其参数。 */
    private fun stripExchangeStatus(
        selection: String,
        args: Array<String?>?
    ): Pair<String?, Array<String>?> {
        val parts = selection.split(" AND ")
        val kept = mutableListOf<String>()
        val keptArgs = mutableListOf<String>()
        var idx = 0
        for (part in parts) {
            val q = part.count { it == '?' }
            if (part.contains("exchangeStatus")) {
                idx += q
            } else {
                kept.add(part)
                repeat(q) {
                    if (args != null && idx < args.size) args[idx]?.let { keptArgs.add(it) }
                    idx++
                }
            }
        }
        val newSel = kept.joinToString(" AND ").ifEmpty { null }
        val newArgs = keptArgs.toTypedArray().ifEmpty { null }
        return newSel to newArgs
    }

    /** com.fido.asm：hook ContentResolver.getSyncAutomatically，miui.autofill 恒真。 */
    private fun hookSyncEnableFido() {
        val method = ContentResolver::class.java.getMethod(
            "getSyncAutomatically", Account::class.java, String::class.java
        )
        hook(method)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                if (SYNC_AUTHORITY == chain.getArg(1)) true else chain.proceed()
            }
        log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name}")
    }

    /** com.fido.asm：旧 UAF 白名单绕过（NokNok FacetIDsValidator 决策点恒真）。 */
    private fun hookNokNokWhitelist(param: PackageReadyParam) {
        val clazz = Class.forName(FACET_ID_VALIDATOR, false, param.classLoader)

        hookReturnsTrue(
            clazz, "isAppTrust", arrayOf(Activity::class.java),
            "FacetIDsValidator.isAppTrust(Activity)"
        )
        hookReturnsTrue(
            clazz, "isAppTrust", arrayOf(Activity::class.java, String::class.java),
            "FacetIDsValidator.isAppTrust(Activity,String)"
        )
        hookReturnsTrue(
            clazz, "isFacetIdInList", arrayOf(String::class.java),
            "FacetIDsValidator.isFacetIdInList(String)"
        )
    }

    /** com.fido.asm：FIDO2 VendorValidator（p2.e.a）整体 no-op，去掉 vendor 校验（browser/app not allow）。 */
    private fun hookFidoVendorValidate(param: PackageReadyParam) {
        val bridge = DexKitBridge.create(param.classLoader, false)
        try {
            val methodData = findMethodByMarker(bridge, "void", 5, "vendor validate failed", false).firstOrNull()
                ?: throw IllegalStateException("VendorValidator method not found")

            val method = methodData.getMethodInstance(param.classLoader)
            hook(method)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { null }

            log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name} (VendorValidator)")
        } finally {
            bridge.close()
        }
    }

    private fun hookReturnsTrue(
        clazz: Class<*>,
        methodName: String,
        paramTypes: Array<Class<*>>,
        context: String
    ) {
        try {
            val method = clazz.getDeclaredMethod(methodName, *paramTypes)
            hook(method)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { true }
            log(Log.INFO, TAG, "hooked $context")
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "skip hook $context: ${t.message}")
        }
    }

    private fun findMethodByMarker(
        bridge: DexKitBridge,
        returnType: String,
        paramCount: Int,
        marker: String,
        requireStatic: Boolean = true
    ) = bridge.findMethod {
        matcher {
            this.returnType = returnType
            this.paramCount = paramCount
            if (requireStatic) {
                modifiers = Modifier.STATIC
            }
            usingStrings(marker)
        }
    }
}
