package com.syncbloker

import android.accounts.Account
import android.app.Activity
import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.credentials.CredentialManager
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialRequest
import android.credentials.CreateCredentialResponse
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Base64
import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.json.JSONObject
import org.luckypray.dexkit.DexKitBridge
import org.luckypray.dexkit.result.FieldUsingType
import java.lang.reflect.Constructor
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.concurrent.Executor
import java.util.WeakHashMap
import org.json.JSONArray

/**
 * LSPosed (API 101) 模块。
 *
 * 1. com.miui.passwords（密码管理）：
 *    a) 让 CredentialSupportHelper.getSyncEnable() 恒返回 true，绕过
 *       “请先开启密码管家，再使用通行密钥”的前置校验。
 *    b) 清除“全部通行密钥”列表 exchangeStatus=0 过滤（只显示已同步记录）：
 *       数据适配器 DATA_MANAGERSecurityStorageAdapter 的查询方法去掉 SQL 里的
 *       exchangeStatus 条件；游标→模型工厂把 exchangeStatus 归零（覆盖 Java 二次过滤）。
 *    c) “通行密钥”页给未同步记录追加“未同步”标识：工厂 hook 里先收集未同步 UUID，
 *       再在 Preference 设 summary 时按 key 命中追加文本。
 *    d) 离线创建的通行密钥本地记录缺 rpId/displayName（只有 credentialId）：创建时在
 *       N2.e.J 插入后从 com.fido.asm 导出凭据元数据回填；并在通行密钥页加载时回填历史
 *       极简记录，使列表显示网址与账号。
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
 *
 * 3. com.android.credentialmanager（小米凭据管理器前端）：
 *    小米把 AOSP 多提供方选择 UI 替换为固定确认对话框，保存/登录位置锁死为默认提供方
 *    （小米密码管家）。AOSP 原生组件（CreateCredentialComponentsKt / GetCredentialComponentsKt
 *    及其状态机、资源、ViewModel 回调）仍完整保留在同一 APK 中，且与 Mi 版入口函数签名一致。
 *    做“签名级重定向”：CreateMiCredentialScreen -> CreateCredentialScreen、
 *    GetMiCredentialScreen -> GetCredentialScreen，并修复小米删减的 Compose 颜色值。见 CredManUiRedirect。
 */
class ModuleMain : XposedModule() {

    companion object {
        private const val TAG = "SyncBloker"
        private const val TARGET_PACKAGE_PASSWORDS = "com.miui.passwords"
        private const val TARGET_PACKAGE_FIDO = "com.fido.asm"
        private const val TARGET_PACKAGE_CREDMAN = "com.android.credentialmanager"
        private const val SYNC_AUTHORITY = "miui.autofill"
        private const val FACET_ID_VALIDATOR = "com.noknok.android.uaf.framework.service.FacetIDsValidator"
        private const val CUSTOM_PREFERENCE = "com.miui.passwords.ui.activity.security.CustomStylePreference"
        private const val PREFERENCE = "androidx.preference.Preference"
        private const val UNSYNC_MARK = "未同步"
        private const val FIDO_URI = "content://miui.autofill/fido_credential_summary_record"
        private const val FIDO_SYNC_URI = "content://miui.autofill/fido_credential_summary_record/sync"
        private const val PUBLIC_KEY_TYPE = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        private const val PUBLIC_KEY_SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE"
        private const val CREATE_PUBLIC_KEY_SUBTYPE =
            "androidx.credentials.BUNDLE_VALUE_SUBTYPE_CREATE_PUBLIC_KEY_CREDENTIAL_REQUEST"
        private const val PUBLIC_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
        private const val PUBLIC_KEY_CLIENT_DATA_HASH = "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
        private const val PUBLIC_KEY_REGISTRATION_RESPONSE_JSON =
            "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON"
    }

    /** 未同步（exchangeStatus != 0）通行密钥的 accountUUID 集合。 */
    private val unsyncedUuids = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /** 已识别为未同步的 Preference 实例（弱引用防泄漏，G 设 summary 时消费）。 */
    private val unsyncedPrefs = WeakHashMap<Any, Boolean>()

    /** 已确认无法从 com.fido.asm 取回元数据的凭据（避免每次进页面重复打 TEE）。 */
    private val failedMetaCreds = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    private val hookedPackages = mutableSetOf<String>()

    init {
        System.loadLibrary("dexkit")
    }

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        log(Log.INFO, TAG, "module loaded, apiVersion=$apiVersion")
    }

    override fun onPackageReady(param: PackageReadyParam) {
        val pkg = param.packageName
        if (pkg !in setOf(TARGET_PACKAGE_PASSWORDS, TARGET_PACKAGE_FIDO, TARGET_PACKAGE_CREDMAN)) return
        if (!hookedPackages.add(pkg)) return

        try {
            when (pkg) {
                TARGET_PACKAGE_PASSWORDS -> {
                    // 共享单个 DexKitBridge：全量解析一次 dex，避免重复扫描拖慢进程启动
                    val bridge = DexKitBridge.create(param.classLoader, false)
                    try {
                        safeHook("syncEnable") { hookSyncEnablePasswords(param, bridge) }
                        safeHook("exchangeStatusFilter") { hookPasskeyExchangeStatusFilter(param, bridge) }
                        safeHook("metadataEnrich") { hookPasskeyMetadataEnrich(param, bridge) }
                        safeHook("unsyncedBadge") { hookPasskeyUnsyncedBadge(param, bridge) }
                    } finally {
                        bridge.close()
                    }
                }
                TARGET_PACKAGE_FIDO -> {
                    safeHook("fidoSync") { hookSyncEnableFido() }
                    safeHook("nokNokWhitelist") { hookNokNokWhitelist(param) }
                    safeHook("vendorValidate") { hookFidoVendorValidate(param) }
                    safeHook("fidoHybridAospCreate") { hookFidoHybridAospCreate(param) }
                    safeHook("fidoHybridBoundaryProbe") { hookFidoHybridBoundaryProbe(param) }
                }
                TARGET_PACKAGE_CREDMAN -> {
                    val redirect = CredManUiRedirect(this) { priority, msg, t ->
                        if (t == null) log(priority, TAG, msg) else log(priority, TAG, msg, t)
                    }
                    safeHook("credmanUiRedirect") { redirect.hook(param) }
                }
            }
            log(Log.INFO, TAG, "hooks installed for $pkg")
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "hook failed for $pkg: ${t.message}", t)
        }
    }

    private fun safeHook(label: String, block: () -> Unit) {
        try {
            block()
        } catch (t: Throwable) {
            log(Log.ERROR, TAG, "$label hook failed: ${t.message}", t)
        }
    }

    /** com.miui.passwords：让 getSyncEnable 恒真（DexKit 按字节码特征定位混淆方法）。 */
    private fun hookSyncEnablePasswords(param: PackageReadyParam, bridge: DexKitBridge) {
        // 特征串 "get sync enable" 唯一对应 getSyncEnable；不做泛化兜底（可能误 hook 其它静态 boolean 方法）
        val methodData = findMethodByMarker(bridge, "boolean", 0, "get sync enable").firstOrNull()
            ?: throw IllegalStateException("getSyncEnable method not found")

        val method = methodData.getMethodInstance(param.classLoader)
        hook(method)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { true }

        log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name}")
    }

    /** com.miui.passwords：清除“全部通行密钥”列表的 exchangeStatus=0 过滤（只显示已同步记录）。 */
    private fun hookPasskeyExchangeStatusFilter(param: PackageReadyParam, bridge: DexKitBridge) {
        // exchangeStatus 设值方法 k(long)，其声明类即通行密钥模型类
        val setterMd = bridge.findMethod {
            matcher {
                returnType = "void"
                paramTypes("long")
                usingStrings("exchangeStatus")
            }
        }.firstOrNull() ?: throw IllegalStateException("exchangeStatus setter not found")
        val setter = setterMd.getMethodInstance(param.classLoader).apply { isAccessible = true }
        val modelClass = setter.declaringClass

        // exchangeStatus / accountUUID 字段（跨版本用 DexKit 解析）
        val exchangeStatusField = setterMd.usingFields
            .firstOrNull { it.usingType == FieldUsingType.Write && it.field.typeName == "long" }
            ?.field?.getFieldInstance(param.classLoader)?.apply { isAccessible = true }
            ?: throw IllegalStateException("exchangeStatus field not found")
        val accountUuidField = bridge.findMethod {
            matcher {
                declaredClass(modelClass)
                returnType = "void"
                paramTypes("java.lang.String")
                usingStrings("accountUUID")
            }
        }.firstOrNull()?.usingFields
            ?.firstOrNull {
                it.usingType == FieldUsingType.Write && it.field.typeName == "java.lang.String"
            }
            ?.field?.getFieldInstance(param.classLoader)?.apply { isAccessible = true }
            ?: throw IllegalStateException("accountUUID field not found")

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
                            // 先记录未同步 UUID，再归零（保证列表全量显示的同时保留同步状态信息）
                            if (exchangeStatusField.getLong(obj) != 0L) {
                                val uuid = accountUuidField.get(obj) as? String
                                if (!uuid.isNullOrEmpty()) {
                                    unsyncedUuids.add(uuid)
                                }
                            }
                            // 注：仅归零内存中的展示模型，不写回数据库；该路径的模型不会被 q()→update 落库，
                            //     同步状态始终以库中原值为准。
                            setter.invoke(obj, 0L)
                        }
                        obj
                    }
                log(Log.INFO, TAG, "hooked ${method.declaringClass.name}.${method.name} (passkey factory)")
            }
    }

    /** 去掉 SQL selection 里的 "exchangeStatus = ?" 条件及其参数（大小写不敏感）。
     *  仅支持顶层 AND/OR 拼接；括号包裹的 exchangeStatus 条件不支持（当前 app 查询均为顶层条件）。 */
    private fun stripExchangeStatus(
        selection: String,
        args: Array<String?>?
    ): Pair<String?, Array<String>?> {
        val parts = selection.split(Regex("\\s+(?i:and|or)\\s+"))
        val kept = mutableListOf<String>()
        val keptArgs = mutableListOf<String>()
        var idx = 0
        for (part in parts) {
            val q = part.count { it == '?' }
            if (part.contains("exchangeStatus", ignoreCase = true)) {
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

    /** com.miui.passwords：离线创建的通行密钥本地记录缺 rpId/displayName（只有 credentialId）。 */
    private fun hookPasskeyMetadataEnrich(param: PackageReadyParam, bridge: DexKitBridge) {
        // 通行密钥模型类 + q()（从字段重建 ContentValues，用于读取/判断极简记录）
        val modelClass = bridge.findMethod {
            matcher {
                returnType = "void"
                paramTypes("long")
                usingStrings("exchangeStatus")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)?.declaringClass
            ?: throw IllegalStateException("passkey model not found")
        val qMethod = bridge.findMethod {
            matcher {
                declaredClass(modelClass)
                paramCount = 0
                returnType = "android.content.ContentValues"
                usingStrings("exchangeStatus")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: throw IllegalStateException("q() not found")

        // N2.e（同步管理）：插入 J + ContentResolver w()
        val syncClass = bridge.findClass {
            matcher { usingStrings("parseTAJSONStringAndUpdateFidoRecord") }
        }.firstOrNull()?.getInstance(param.classLoader)
            ?: throw IllegalStateException("sync manager not found")
        val jMethod = bridge.findMethod {
            matcher {
                declaredClass(syncClass)
                paramCount = 1
                usingStrings("insert fido to local db")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)
            ?: throw IllegalStateException("N2.e.J not found")
        val wMethod = bridge.findMethod {
            matcher {
                declaredClass(syncClass)
                paramCount = 0
                returnType = "android.content.ContentResolver"
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: throw IllegalStateException("N2.e.w not found")

        // com.fido.asm 导出代理 N2.d：构造 + f(List)
        val proxyClass = bridge.findClass {
            matcher { usingStrings("start operation fido export interface") }
        }.firstOrNull()?.getInstance(param.classLoader)
            ?: throw IllegalStateException("fido proxy not found")
        val proxyCtor = proxyClass.getConstructor(Int::class.java).apply { isAccessible = true }
        val exportMethod = bridge.findMethod {
            matcher {
                declaredClass(proxyClass)
                paramCount = 1
                paramTypes("java.util.List")
                usingStrings("start operation fido export interface")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: throw IllegalStateException("N2.d.f not found")

        // 通行密钥页数据加载 loadPasskeysData i(Context)（用于回填历史极简记录，兼作创建时竞态兜底）
        // 注意：不先 findClass——该日志 tag 被类的大量合成内部类共用，firstOrNull 会取错类；
        // 直接用特征串 + 签名定位方法。
        val loadPasskeysMethod = bridge.findMethod {
            matcher {
                paramCount = 1
                paramTypes("android.content.Context")
                usingStrings("loadPasskeysData records count")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)
        if (loadPasskeysMethod == null) {
            log(Log.WARN, TAG, "loadPasskeysData method not found, backfill disabled")
        }

        // 创建时补全（:sync 进程，CredentialPassService 插入路径）
        hook(jMethod)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val record = chain.getArg(0)
                val qcv = try {
                    qMethod.invoke(record) as? ContentValues
                } catch (t: Throwable) {
                    null
                }
                val credentialId = qcv?.getAsString("credentialId")
                val rpId = qcv?.getAsString("rpId")
                val result = chain.proceed()
                if (!credentialId.isNullOrEmpty() && rpId.isNullOrEmpty()) {
                    enrichOne(chain.thisObject, credentialId, proxyCtor, exportMethod, wMethod)
                }
                result
            }
        log(Log.INFO, TAG, "hooked ${jMethod.declaringClass.name}.${jMethod.name} (metadata enrich)")

        // 页面加载时回填历史极简记录
        if (loadPasskeysMethod != null) {
            hook(loadPasskeysMethod)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { chain ->
                    val result = chain.proceed()
                    val context = chain.getArg(0) as? Context
                    if (context != null) {
                        try {
                            val appCtx = context.applicationContext
                            Thread { backfillMinimalPasskeys(appCtx, proxyCtor, exportMethod) }.start()
                        } catch (t: Throwable) {
                            log(Log.WARN, TAG, "backfill trigger failed: ${t.message}")
                        }
                    }
                    result
                }
            log(Log.INFO, TAG, "hooked ${loadPasskeysMethod.declaringClass.name}.${loadPasskeysMethod.name} (backfill)")
        }
    }

    /** 单个凭据：export 取元数据 → 更新本地行。 */
    private fun enrichOne(
        owner: Any?,
        credentialId: String,
        proxyCtor: Constructor<*>,
        exportMethod: Method,
        wMethod: Method
    ) {
        try {
            val proxy = proxyCtor.newInstance(0)
            val exported = exportMethod.invoke(proxy, listOf(credentialId)) as? List<*>
            val json = exported?.firstOrNull() as? String ?: return
            val obj = JSONObject(json)
            if (obj.optInt("status", -1) != 0) return
            val resolver = wMethod.invoke(owner) as? ContentResolver
            val cv = ContentValues()
            cv.put("rpId", obj.optString("rpId"))
            cv.put("fidoUniqueId", obj.optString("fidoUniqueId"))
            cv.put("displayName", obj.optString("displayName"))
            cv.put("packageName", obj.optString("packageName"))
            resolver?.update(
                Uri.parse(FIDO_SYNC_URI), cv, "credentialId = ?", arrayOf(credentialId)
            )
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "enrich passkey metadata failed for $credentialId: ${t.message}")
        }
    }

    /** 回填历史极简记录（主进程，通行密钥页加载时触发一次，成功后不再有极简记录）。 */
    private fun backfillMinimalPasskeys(
        context: Context,
        proxyCtor: Constructor<*>,
        exportMethod: Method
    ) {
        try {
            val resolver = context.contentResolver
            val uri = Uri.parse(FIDO_URI)
            val ids = ArrayList<String>()
            resolver.query(
                uri, arrayOf("credentialId"),
                "credentialId IS NOT NULL AND (rpId IS NULL OR rpId = '')",
                null, null
            )?.use { c ->
                while (c.moveToNext()) {
                    val id = c.getString(c.getColumnIndex("credentialId"))
                    if (!id.isNullOrEmpty()) ids.add(id)
                }
            }
            if (ids.isEmpty()) {
                return
            }
            ids.removeAll(failedMetaCreds)
            if (ids.isEmpty()) {
                return
            }
            val proxy = proxyCtor.newInstance(0)
            val exported = exportMethod.invoke(proxy, ids) as? List<*>
            if (exported == null || exported.size != ids.size) {
                return
            }
            for (i in exported.indices) {
                val json = exported[i] as? String ?: continue
                val obj = try {
                    JSONObject(json)
                } catch (t: Throwable) {
                    continue
                }
                if (obj.optInt("status", -1) != 0) {
                    failedMetaCreds.add(ids[i])
                    log(Log.WARN, TAG, "credential not recoverable, cached: ${ids[i]}")
                    continue
                }
                val cv = ContentValues()
                cv.put("rpId", obj.optString("rpId"))
                cv.put("fidoUniqueId", obj.optString("fidoUniqueId"))
                cv.put("displayName", obj.optString("displayName"))
                cv.put("packageName", obj.optString("packageName"))
                val cid = obj.optString("credentialId").ifEmpty { ids[i] }
                resolver.update(uri, cv, "credentialId = ?", arrayOf(cid))
            }
        } catch (t: Throwable) {
            log(Log.WARN, TAG, "backfill failed: ${t.message}")
        }
    }

    /** com.miui.passwords：“通行密钥”页给未同步记录追加“未同步”标识（方案A：summary 文本）。 */
    private fun hookPasskeyUnsyncedBadge(param: PackageReadyParam, bridge: DexKitBridge) {
        // CustomStylePreference.setSummary 覆盖方法 G(CharSequence)
        val summarySetter = bridge.findMethod {
            matcher {
                declaredClass(CUSTOM_PREFERENCE)
                paramCount = 1
                paramTypes("java.lang.CharSequence")
            }
        }.firstOrNull()?.getMethodInstance(param.classLoader)
            ?: throw IllegalStateException("summary setter not found")
        hook(summarySetter)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                if (unsyncedPrefs.remove(chain.thisObject) == true) {
                    val base = chain.getArg(0) as? CharSequence
                    val marked = if (base.isNullOrEmpty()) UNSYNC_MARK else "$base · $UNSYNC_MARK"
                    chain.proceed(arrayOf(marked))
                } else {
                    chain.proceed()
                }
            }
        log(Log.INFO, TAG, "hooked ${summarySetter.declaringClass.name}.${summarySetter.name} (unsynced badge)")

        // androidx.preference.Preference 的 String 单参设值方法（setKey 等混淆名）：
        // 运行时按“参数命中未同步集合”识别通行密钥 key 设值，标记该实例
        bridge.findMethod {
            matcher {
                declaredClass(PREFERENCE)
                paramCount = 1
                paramTypes("java.lang.String")
            }
        }.forEach { md ->
            val method = md.getMethodInstance(param.classLoader)
            hook(method)
                .setPriority(XposedInterface.PRIORITY_HIGHEST)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { chain ->
                    val key = chain.getArg(0) as? String
                    if (key != null && key in unsyncedUuids) {
                        unsyncedPrefs[chain.thisObject] = true
                    }
                    chain.proceed()
                }
        }
        log(Log.INFO, TAG, "hooked Preference string setters (passkey key detect)")
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

    /**
     * 扫码连电脑的只读探针：记录 Hybrid CTAP 请求进入本地 authenticator 的边界，
     * 不改变任何返回值或控制流。这个位置用于确认：电脑请求是否已经解析成 b3.u，
     * 以及在真正生成/保存凭据前当前选择的 authenticator 是谁。
     */
    private fun hookFidoHybridBoundaryProbe(param: PackageReadyParam) {
        val cl = param.classLoader
        val requestClass = Class.forName("b3.m0", false, cl)
        // JADX 展示名是 InterfaceC0115a，但 dex 的真实内部类名是 m2.a$a。
        val callbackClass = Class.forName("m2.a\$a", false, cl)
        val executorClass = Class.forName("j2.h", false, cl)
        val strategyClass = Class.forName("m2.d", false, cl)
        val boundary = strategyClass.getDeclaredMethod(
            "h",
            executorClass,
            requestClass,
            callbackClass,
        ).apply { isAccessible = true }

        hook(boundary)
            .setPriority(XposedInterface.PRIORITY_LOWEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val request = chain.getArg(1)
                log(Log.INFO, TAG, "QR boundary request=${describeHybridRequest(request)}")
                chain.proceed()
            }

        // 同一条链路的下一层：读取当前将实际执行的 authenticator，仅用于确认是否仍是小米 passkey。
        val teeClass = Class.forName("a2.a", false, cl)
        val exec = teeClass.getDeclaredMethod("exec", Byte::class.javaPrimitiveType, requestClass)
            .apply { isAccessible = true }
        val getAuthenticator = teeClass.getDeclaredMethod("getAuthenticator")
            .apply { isAccessible = true }

        hook(exec)
            .setPriority(XposedInterface.PRIORITY_LOWEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val authenticator = runCatching {
                    getAuthenticator.invoke(chain.thisObject)?.javaClass?.name
                }.getOrNull()
                log(
                    Log.INFO,
                    TAG,
                    "QR authenticator exec command=${chain.getArg(0)} selected=$authenticator " +
                        "request=${describeHybridRequest(chain.getArg(1))}",
                )
                chain.proceed()
            }

        log(Log.INFO, TAG, "hooked FIDO Hybrid boundary probe")
    }

    /**
     * 扫码连电脑的 MakeCredential 先交给系统 CredentialManager。
     *
     * Hybrid 的 CTAP 请求只有 clientDataHash，没有浏览器侧的完整 clientDataJSON，
     * 所以这里用一个合法的 WebAuthn options JSON 作为 provider 的输入，同时把原始
     * clientDataHash 放入 AndroidX/AOSP 约定的 bundle。provider 返回的
     * attestationObject 本身就是 CTAP MakeCredential 的 CBOR payload，前面补成功状态
     * 字节即可交回 Hybrid executor。GetAssertion 暂时继续走原来的小米路径。
     */
    private fun hookFidoHybridAospCreate(param: PackageReadyParam) {
        val cl = param.classLoader
        val requestClass = Class.forName("b3.m0", false, cl)
        val callbackClass = Class.forName("m2.a\$a", false, cl)
        val executorClass = Class.forName("j2.h", false, cl)
        val strategyClass = Class.forName("m2.d", false, cl)
        val boundary = strategyClass.getDeclaredMethod(
            "h",
            executorClass,
            requestClass,
            callbackClass,
        ).apply { isAccessible = true }

        hook(boundary)
            .setPriority(XposedInterface.PRIORITY_HIGHEST)
            .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
            .intercept { chain ->
                val request = chain.getArg(1)
                if (request?.javaClass?.name != "b3.u") {
                    chain.proceed()
                } else {
                    val callback = chain.getArg(2)
                    val applicationContext = readField(chain.thisObject, "f8539a", "a") as? Context
                    val context = resolveHybridActivity(chain.getArg(0)) ?: applicationContext
                    if (callback == null || context == null) {
                        log(Log.WARN, TAG, "AOSP create bridge: missing callback/context, fallback Xiaomi")
                        chain.proceed()
                    } else {
                        try {
                            if (launchAospCreate(context, request, callback)) {
                                null
                            } else {
                                log(Log.WARN, TAG, "AOSP create bridge: request conversion failed, fallback Xiaomi")
                                chain.proceed()
                            }
                        } catch (t: Throwable) {
                            log(Log.WARN, TAG, "AOSP create bridge failed, fallback Xiaomi: ${t.message}")
                            chain.proceed()
                        }
                    }
                }
        }

        log(Log.INFO, TAG, "hooked FIDO Hybrid MakeCredential -> AOSP CredentialManager")
    }

    private fun resolveHybridActivity(executor: Any?): Activity? {
        val activityState = readField(executor, "f6686b", "b") ?: return null
        return runCatching {
            activityState.javaClass.getMethod("j").invoke(activityState) as? Activity
        }.getOrNull()
    }

    private fun launchAospCreate(context: Context, request: Any, callback: Any): Boolean {
        val requestJson = buildCreateRequestJson(request) ?: return false
        val clientDataHash = readField(request, "f2631a", "a") as? ByteArray ?: return false
        if (clientDataHash.isEmpty()) return false

        val credentialData = Bundle().apply {
            putString(PUBLIC_KEY_SUBTYPE, CREATE_PUBLIC_KEY_SUBTYPE)
            putString(PUBLIC_KEY_REQUEST_JSON, requestJson)
            putByteArray(PUBLIC_KEY_CLIENT_DATA_HASH, clientDataHash)
        }
        val candidateQueryData = Bundle(credentialData)
        val frameworkRequest = CreateCredentialRequest.Builder(
            PUBLIC_KEY_TYPE,
            credentialData,
            candidateQueryData,
        )
            .setAlwaysSendAppInfoToProvider(true)
            .build()
        val manager = context.getSystemService(CredentialManager::class.java) ?: return false
        val executor: Executor = context.mainExecutor

        log(
            Log.INFO,
            TAG,
            "AOSP create bridge launch rp=${readField(readField(request, "f2632b", "b"), "id")}" +
                " user=${readField(readField(request, "f2633c", "c"), "name")}",
        )
        manager.createCredential(
            context,
            frameworkRequest,
            null as CancellationSignal?,
            executor,
            object : OutcomeReceiver<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(result: CreateCredentialResponse) {
                    try {
                        val responseJson = result.data.getString(PUBLIC_KEY_REGISTRATION_RESPONSE_JSON)
                        val attestationObject = responseJson
                            ?.let { JSONObject(it).optString("attestationObject") }
                            ?.takeIf { it.isNotEmpty() }
                            ?.let { decodeBase64Url(it) }
                        if (attestationObject == null || attestationObject.isEmpty()) {
                            log(Log.ERROR, TAG, "AOSP create bridge: provider returned no attestationObject")
                            invokeHybridError(callback, 127)
                            return
                        }
                        val ctapResponse = ByteArray(attestationObject.size + 1)
                        ctapResponse[0] = 0
                        System.arraycopy(attestationObject, 0, ctapResponse, 1, attestationObject.size)
                        log(Log.INFO, TAG, "AOSP create bridge success attestationBytes=${attestationObject.size}")
                        invokeHybridSuccess(callback, ctapResponse)
                    } catch (t: Throwable) {
                        log(Log.ERROR, TAG, "AOSP create bridge response conversion failed: ${t.message}", t)
                        invokeHybridError(callback, 127)
                    }
                }

                override fun onError(error: CreateCredentialException) {
                    log(Log.WARN, TAG, "AOSP create bridge provider error: ${error.message}")
                    invokeHybridError(callback, 127)
                }
            },
        )
        return true
    }

    private fun buildCreateRequestJson(request: Any): String? {
        val rp = readField(request, "f2632b", "b") ?: return null
        val user = readField(request, "f2633c", "c") ?: return null
        val rpId = readField(rp, "id") as? String ?: return null
        val userId = readField(user, "id") as? ByteArray ?: return null
        val userName = readField(user, "name") as? String ?: return null
        val clientDataHash = readField(request, "f2631a", "a") as? ByteArray ?: return null

        val json = JSONObject()
        json.put("challenge", encodeBase64Url(clientDataHash))
        json.put("rp", JSONObject().apply {
            put("id", rpId)
            (readField(rp, "name") as? String)?.let { put("name", it) }
        })
        json.put("user", JSONObject().apply {
            put("id", encodeBase64Url(userId))
            put("name", userName)
            put("displayName", (readField(user, "displayName") as? String).orEmpty().ifEmpty { userName })
        })

        val parameters = JSONArray()
        val parameterList = readField(request, "f2634d", "d") as? Iterable<*>
        parameterList?.forEach { parameter ->
            val algorithm = readAlgorithm(parameter) ?: return@forEach
            parameters.put(JSONObject().apply {
                put("type", "public-key")
                put("alg", algorithm)
            })
        }
        if (parameters.length() == 0) return null
        json.put("pubKeyCredParams", parameters)

        val excludeList = readField(request, "f2635e", "e") as? Iterable<*>
        if (excludeList != null) {
            val exclude = JSONArray()
            excludeList.forEach { descriptor ->
                val id = readField(descriptor, "id") as? ByteArray ?: return@forEach
                exclude.put(JSONObject().apply {
                    put("type", "public-key")
                    put("id", encodeBase64Url(id))
                })
            }
            if (exclude.length() > 0) json.put("excludeCredentials", exclude)
        }

        val options = readField(request, "f2637g", "g")
        val residentKey = readBoolean(options, "f2641a", "a")
        val userVerification = readBoolean(options, "f2642b", "b")
        if (residentKey != null || userVerification != null) {
            json.put("authenticatorSelection", JSONObject().apply {
                residentKey?.let { put("residentKey", if (it) "required" else "discouraged") }
                residentKey?.let { put("requireResidentKey", it) }
                userVerification?.let { put("userVerification", if (it) "required" else "discouraged") }
            })
        }
        json.put("attestation", "none")
        return json.toString()
    }

    private fun readAlgorithm(parameter: Any?): Int? {
        val algorithm = readField(parameter, "alg") ?: return null
        return runCatching {
            (algorithm.javaClass.getMethod("h").invoke(algorithm) as Number).toInt()
        }.getOrNull()
    }

    private fun readBoolean(instance: Any?, vararg names: String): Boolean? =
        (readField(instance, *names) as? Boolean)

    private fun invokeHybridSuccess(callback: Any, bytes: ByteArray) {
        callback.javaClass.getMethod("a", ByteArray::class.java).invoke(callback, bytes)
    }

    private fun invokeHybridError(callback: Any, status: Int) {
        callback.javaClass.getMethod("b", Byte::class.javaPrimitiveType).invoke(callback, status.toByte())
    }

    private fun encodeBase64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun decodeBase64Url(value: String): ByteArray =
        Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun describeHybridRequest(request: Any?): String {
        if (request == null) return "null"
        val type = request.javaClass.name
        if (type != "b3.u") return "type=$type"
        // JADX 显示的是反混淆字段名，运行时 dex 中仍是 a/b/c。
        val clientDataHash = readField(request, "f2631a", "a") as? ByteArray
        val rp = readField(request, "f2632b", "b")
        val user = readField(request, "f2633c", "c")
        val rpId = readField(rp, "id") as? String
        val userId = readField(user, "id") as? ByteArray
        return "type=$type hashBytes=${clientDataHash?.size ?: -1} " +
            "rpId=$rpId userIdBytes=${userId?.size ?: -1}"
    }

    private fun readField(instance: Any?, vararg names: String): Any? {
        if (instance == null) return null
        for (name in names) {
            var type: Class<*>? = instance.javaClass
            while (type != null) {
                try {
                    return type.getDeclaredField(name).apply { isAccessible = true }.get(instance)
                } catch (_: NoSuchFieldException) {
                    type = type.superclass
                } catch (_: Throwable) {
                    break
                }
            }
        }
        return null
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
