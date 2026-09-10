package com.hyperpasskeyfix.aosp

import android.accounts.Account
import android.app.Activity
import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.json.JSONObject
import org.luckypray.dexkit.DexKitBridge
import org.luckypray.dexkit.result.FieldUsingType
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Xiaomi account/sync restrictions and the optional legacy password-manager data repair.
 * The password-manager package is deliberately not a recommended scope.
 */
internal class SyncValidationHooks(private val runtime: HookRuntime) {
    private val unsyncedUuids = ConcurrentHashMap.newKeySet<String>()
    private val failedMetadataIds = ConcurrentHashMap.newKeySet<String>()
    private val unsyncedPreferences = Collections.synchronizedMap(WeakHashMap<Any, Boolean>())
    private val backfillRunning = AtomicBoolean(false)
    private val backfillExecutor by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        Executors.newSingleThreadExecutor { task ->
            Thread(task, "HyperPasskeyMetadata").apply { isDaemon = true }
        }
    }

    fun installForPasswords(param: PackageReadyParam, bridge: DexKitBridge) {
        runtime.attempt("password-manager sync check") {
            hookPasswordManagerSyncCheck(param, bridge)
        }
        var modelTarget: PasswordModelTarget? = null
        runtime.attempt("password-manager passkey model") {
            modelTarget = resolvePasswordModel(param, bridge)
        }
        modelTarget?.let { target ->
            runtime.attempt("password-manager unsynced records") {
                hookUnsyncedRecordVisibility(param, bridge, target)
            }
            runtime.attempt("password-manager metadata repair") {
                hookMetadataRepair(param, bridge, target)
            }
        }
        runtime.attempt("password-manager unsynced label") {
            hookUnsyncedLabel(param, bridge)
        }
    }

    fun installForFido(param: PackageReadyParam, bridge: DexKitBridge) {
        runtime.attempt("FIDO sync check") { hookFrameworkSyncCheck() }
        runtime.attempt("FIDO UAF caller trust") { hookUafCallerTrust(param, bridge) }
        runtime.attempt("FIDO vendor validation") { hookVendorValidation(param, bridge) }
    }

    private fun hookPasswordManagerSyncCheck(param: PackageReadyParam, bridge: DexKitBridge) {
        val method = findMethodByMarker(bridge, "boolean", 0, "get sync enable")
            ?.getMethodInstance(param.classLoader)
            ?: error("sync-state method not found")

        runtime.hook(method)
            .intercept { true }
    }

    private fun resolvePasswordModel(
        param: PackageReadyParam,
        bridge: DexKitBridge,
    ): PasswordModelTarget {
        val setterData = bridge.findMethod {
            findFirst = true
            matcher {
                returnType = "void"
                paramTypes("long")
                usingStrings("exchangeStatus")
            }
        }.singleOrNull() ?: error("exchangeStatus setter not found")
        val setter = setterData.getMethodInstance(param.classLoader).apply { isAccessible = true }
        val modelClass = setter.declaringClass
        val exchangeStatusField = setterData.usingFields
            .firstOrNull { it.usingType == FieldUsingType.Write && it.field.typeName == "long" }
            ?.field?.getFieldInstance(param.classLoader)?.apply { isAccessible = true }
            ?: error("exchangeStatus field not found")
        return PasswordModelTarget(modelClass, setter, exchangeStatusField)
    }

    private fun hookUnsyncedRecordVisibility(
        param: PackageReadyParam,
        bridge: DexKitBridge,
        target: PasswordModelTarget,
    ) {
        val modelData = bridge.getClassData(target.type) ?: error("passkey model dex data not found")

        val accountUuidField = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(modelData))
            matcher {
                returnType = "void"
                paramTypes("java.lang.String")
                usingStrings("accountUUID")
            }
        }.singleOrNull()?.usingFields
            ?.firstOrNull {
                it.usingType == FieldUsingType.Write && it.field.typeName == "java.lang.String"
            }
            ?.field?.getFieldInstance(param.classLoader)?.apply { isAccessible = true }
            ?: error("accountUUID field not found")

        val queryMethod = bridge.findMethod {
            findFirst = true
            matcher {
                paramTypes("java.lang.Class", "java.lang.String", "java.lang.String[]")
                usingStrings("Query failed: ")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)
            ?: error("passkey query method not found")
        runtime.hook(queryMethod)
            .intercept { chain ->
                val requestedClass = chain.getArg(0)
                val selection = chain.getArg(1) as? String
                if (requestedClass != target.type || selection?.contains("exchangeStatus", true) != true) {
                    chain.proceed()
                } else {
                    val selectionArgs = (chain.getArg(2) as? Array<*>)
                        ?.map { it as? String }
                        ?.toTypedArray()
                    val (newSelection, newArgs) = stripExchangeStatus(selection, selectionArgs)
                    chain.proceed(arrayOf(requestedClass, newSelection, newArgs))
                }
            }

        val factoryMethod = bridge.findMethod {
            findFirst = true
            matcher {
                paramTypes("android.database.Cursor", "java.lang.Class")
                usingStrings("Unsupported model: ")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)
            ?: error("passkey model factory not found")
        runtime.hook(factoryMethod)
            .intercept { chain ->
                val model = chain.proceed()
                if (target.type.isInstance(model)) {
                    val unsynced = target.exchangeStatusField.getLong(model) != 0L
                    (accountUuidField.get(model) as? String)
                        ?.takeIf(String::isNotEmpty)
                        ?.let { uuid ->
                            if (unsynced) {
                                unsyncedUuids += uuid
                            } else {
                                unsyncedUuids -= uuid
                            }
                        }
                    // Change only the in-memory display model; the database remains authoritative.
                    if (unsynced) {
                        target.exchangeStatusSetter.invoke(model, 0L)
                    }
                }
                model
            }
    }

    private fun stripExchangeStatus(
        selection: String,
        args: Array<String?>?,
    ): Pair<String?, Array<String>?> {
        val keptClauses = ArrayList<String>()
        val keptArgs = ArrayList<String>()
        var argumentIndex = 0
        for (clause in selection.split(SQL_BOOLEAN_OPERATOR)) {
            val placeholders = clause.count { it == '?' }
            if (clause.contains("exchangeStatus", ignoreCase = true)) {
                argumentIndex += placeholders
                continue
            }
            keptClauses += clause
            repeat(placeholders) {
                args?.getOrNull(argumentIndex)?.let(keptArgs::add)
                argumentIndex++
            }
        }
        return keptClauses.joinToString(" AND ").ifEmpty { null } to
            keptArgs.toTypedArray().ifEmpty { null }
    }

    private fun hookMetadataRepair(
        param: PackageReadyParam,
        bridge: DexKitBridge,
        target: PasswordModelTarget,
    ) {
        val modelData = bridge.getClassData(target.type) ?: error("passkey model dex data not found")
        val toValues = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(modelData))
            matcher {
                paramCount = 0
                returnType = "android.content.ContentValues"
                usingStrings("exchangeStatus")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: error("passkey ContentValues converter not found")

        val syncClassData = bridge.findClass {
            findFirst = true
            matcher { usingStrings("parseTAJSONStringAndUpdateFidoRecord") }
        }.singleOrNull() ?: error("password-manager sync class not found")
        val insertMethod = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(syncClassData))
            matcher {
                paramCount = 1
                usingStrings("insert fido to local db")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)
            ?: error("passkey insert method not found")
        val resolverMethod = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(syncClassData))
            matcher {
                paramCount = 0
                returnType = "android.content.ContentResolver"
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: error("ContentResolver accessor not found")

        val proxyClassData = bridge.findClass {
            findFirst = true
            matcher { usingStrings("start operation fido export interface") }
        }.singleOrNull() ?: error("FIDO export proxy not found")
        val proxyClass = proxyClassData.getInstance(param.classLoader)
            ?: error("FIDO export proxy not found")
        val proxyConstructor = proxyClass.getConstructor(Int::class.java).apply { isAccessible = true }
        val exportMethod = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(proxyClassData))
            matcher {
                paramTypes("java.util.List")
                usingStrings("start operation fido export interface")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)?.apply { isAccessible = true }
            ?: error("FIDO export method not found")

        val loadMethod = bridge.findMethod {
            findFirst = true
            matcher {
                paramTypes("android.content.Context")
                usingStrings("loadPasskeysData records count")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)

        runtime.hook(insertMethod)
            .intercept { chain ->
                val values = runCatching {
                    toValues.invoke(chain.getArg(0)) as? ContentValues
                }.getOrNull()
                val credentialId = values?.getAsString("credentialId")
                val missingRpId = values?.getAsString("rpId").isNullOrEmpty()
                val result = chain.proceed()
                if (!credentialId.isNullOrEmpty() && missingRpId) {
                    enrichOne(
                        chain.thisObject,
                        credentialId,
                        proxyConstructor,
                        exportMethod,
                        resolverMethod,
                    )
                }
                result
            }

        if (loadMethod != null) {
            runtime.hook(loadMethod)
                .intercept { chain ->
                    val result = chain.proceed()
                    val context = chain.getArg(0) as? Context
                    if (context != null && backfillRunning.compareAndSet(false, true)) {
                        backfillExecutor.execute {
                            try {
                                backfillMinimalRecords(
                                    context.applicationContext,
                                    proxyConstructor,
                                    exportMethod,
                                )
                            } finally {
                                backfillRunning.set(false)
                            }
                        }
                    }
                    result
                }
        }
    }

    private fun enrichOne(
        owner: Any?,
        credentialId: String,
        proxyConstructor: Constructor<*>,
        exportMethod: Method,
        resolverMethod: Method,
    ) {
        runCatching {
            val exported = exportMethod.invoke(
                proxyConstructor.newInstance(0),
                listOf(credentialId),
            ) as? List<*>
            val response = (exported?.firstOrNull() as? String)?.let(::JSONObject) ?: return
            if (response.optInt("status", -1) != 0) return
            val values = response.toMetadataValues()
            (resolverMethod.invoke(owner) as? ContentResolver)?.update(
                Uri.parse(FIDO_SYNC_URI),
                values,
                "credentialId = ?",
                arrayOf(credentialId),
            )
        }.onFailure { runtime.warning("passkey metadata repair failed", it) }
    }

    private fun backfillMinimalRecords(
        context: Context,
        proxyConstructor: Constructor<*>,
        exportMethod: Method,
    ) {
        runCatching {
            val resolver = context.contentResolver
            val uri = Uri.parse(FIDO_URI)
            val ids = ArrayList<String>()
            resolver.query(
                uri,
                arrayOf("credentialId"),
                "credentialId IS NOT NULL AND (rpId IS NULL OR rpId = '')",
                null,
                null,
            )?.use { cursor ->
                val idColumn = cursor.getColumnIndex("credentialId")
                while (idColumn >= 0 && cursor.moveToNext()) {
                    cursor.getString(idColumn)?.takeIf(String::isNotEmpty)?.let(ids::add)
                }
            }
            ids.removeAll(failedMetadataIds)
            if (ids.isEmpty()) return

            val exported = exportMethod.invoke(proxyConstructor.newInstance(0), ids) as? List<*>
                ?: return
            if (exported.size != ids.size) return
            exported.forEachIndexed { index, value ->
                val response = (value as? String)?.let { runCatching { JSONObject(it) }.getOrNull() }
                    ?: return@forEachIndexed
                if (response.optInt("status", -1) != 0) {
                    failedMetadataIds += ids[index]
                    return@forEachIndexed
                }
                val credentialId = response.optString("credentialId").ifEmpty { ids[index] }
                resolver.update(
                    uri,
                    response.toMetadataValues(),
                    "credentialId = ?",
                    arrayOf(credentialId),
                )
            }
        }.onFailure { runtime.warning("historical passkey metadata repair failed", it) }
    }

    private fun JSONObject.toMetadataValues() = ContentValues().also { values ->
        values.put("rpId", optString("rpId"))
        values.put("fidoUniqueId", optString("fidoUniqueId"))
        values.put("displayName", optString("displayName"))
        values.put("packageName", optString("packageName"))
    }

    private fun hookUnsyncedLabel(param: PackageReadyParam, bridge: DexKitBridge) {
        val customPreference = bridge.getClassData(CUSTOM_PREFERENCE)
            ?: error("custom preference dex data not found")
        val summarySetter = bridge.findMethod {
            findFirst = true
            searchInClass(listOf(customPreference))
            matcher {
                paramTypes("java.lang.CharSequence")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)
            ?: error("preference summary setter not found")
        runtime.hook(summarySetter)
            .intercept { chain ->
                if (unsyncedPreferences.remove(chain.thisObject) != true) {
                    chain.proceed()
                } else {
                    val summary = chain.getArg(0) as? CharSequence
                    val marked = if (summary.isNullOrEmpty()) UNSYNCED_LABEL else "$summary · $UNSYNCED_LABEL"
                    chain.proceed(arrayOf(marked))
                }
            }

        val preference = bridge.getClassData(ANDROIDX_PREFERENCE)
            ?: error("AndroidX preference dex data not found")
        bridge.findMethod {
            searchInClass(listOf(preference))
            matcher {
                paramTypes("java.lang.String")
            }
        }.forEach { data ->
            val method = data.getMethodInstance(param.classLoader)
            runtime.hook(method)
                .intercept { chain ->
                    val key = chain.getArg(0) as? String
                    if (key != null && key in unsyncedUuids) {
                        unsyncedPreferences[chain.thisObject] = true
                    } else {
                        unsyncedPreferences.remove(chain.thisObject)
                    }
                    chain.proceed()
                }
        }
    }

    private fun hookFrameworkSyncCheck() {
        val method = ContentResolver::class.java.getMethod(
            "getSyncAutomatically",
            Account::class.java,
            String::class.java,
        )
        runtime.hook(method)
            .intercept { chain ->
                if (chain.getArg(1) == SYNC_AUTHORITY) true else chain.proceed()
            }
    }

    private fun hookUafCallerTrust(param: PackageReadyParam, bridge: DexKitBridge) {
        val validator = bridge.findClass {
            findFirst = true
            searchPackages("com.noknok.android.uaf.framework.service")
            matcher { usingStrings("gmrzList", "whiteList") }
        }.singleOrNull()?.getInstance(param.classLoader)
            ?: error("UAF facet validator not found")

        hookReturnsTrue(validator, "isAppTrust", arrayOf(Activity::class.java))
        hookReturnsTrue(
            validator,
            "isAppTrust",
            arrayOf(Activity::class.java, String::class.java),
        )
        hookReturnsTrue(validator, "isFacetIdInList", arrayOf(String::class.java))
    }

    private fun hookReturnsTrue(
        type: Class<*>,
        name: String,
        parameterTypes: Array<Class<*>>,
    ) {
        val method = type.getDeclaredMethod(name, *parameterTypes).apply { isAccessible = true }
        runtime.hook(method)
            .intercept { true }
    }

    private fun hookVendorValidation(param: PackageReadyParam, bridge: DexKitBridge) {
        val method = findMethodByMarker(
            bridge = bridge,
            returnType = "void",
            parameterCount = 5,
            marker = "vendor validate failed",
            requireStatic = false,
        )?.getMethodInstance(param.classLoader)
            ?: error("FIDO vendor validator not found")

        runtime.hook(method)
            .intercept { null }
    }

    private fun findMethodByMarker(
        bridge: DexKitBridge,
        returnType: String,
        parameterCount: Int,
        marker: String,
        requireStatic: Boolean = true,
    ) = bridge.findMethod {
        findFirst = true
        matcher {
            this.returnType = returnType
            this.paramCount = parameterCount
            if (requireStatic) modifiers = Modifier.STATIC
            usingStrings(marker)
        }
    }.singleOrNull()

    private companion object {
        const val SYNC_AUTHORITY = "miui.autofill"
        const val CUSTOM_PREFERENCE =
            "com.miui.passwords.ui.activity.security.CustomStylePreference"
        const val ANDROIDX_PREFERENCE = "androidx.preference.Preference"
        const val UNSYNCED_LABEL = "未同步"
        const val FIDO_URI = "content://miui.autofill/fido_credential_summary_record"
        const val FIDO_SYNC_URI =
            "content://miui.autofill/fido_credential_summary_record/sync"
        val SQL_BOOLEAN_OPERATOR = Regex("\\s+(?i:and|or)\\s+")
    }

    private data class PasswordModelTarget(
        val type: Class<*>,
        val exchangeStatusSetter: Method,
        val exchangeStatusField: Field,
    )
}
