package com.hyperpasskeyfix.aosp

import android.annotation.SuppressLint
import android.app.Activity
import android.credentials.CredentialManager
import android.credentials.CredentialOption
import android.credentials.CreateCredentialException
import android.credentials.CreateCredentialRequest
import android.credentials.CreateCredentialResponse
import android.credentials.GetCredentialException
import android.credentials.GetCredentialRequest
import android.credentials.GetCredentialResponse
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.service.credentials.CallingAppInfo
import android.util.Base64
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import org.json.JSONArray
import org.json.JSONObject
import org.luckypray.dexkit.DexKitBridge
import java.io.ByteArrayOutputStream
import java.lang.ref.WeakReference
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.util.IdentityHashMap
import java.util.concurrent.ConcurrentHashMap

/** QR/cross-device CTAP requests bridged from Xiaomi Hybrid FIDO to AOSP CredentialManager. */
@SuppressLint("NewApi") // ModuleMain instantiates this class only on Android 14+.
internal class HybridPasskeyHooks(private val runtime: HookRuntime) {
    private val serializers = ConcurrentHashMap<Class<*>, Method>()

    fun installForFido(param: PackageReadyParam, bridge: DexKitBridge) {
        runtime.attempt("Hybrid CredentialManager bridge") {
            hookHybridBoundary(param, bridge)
        }
    }

    /** Optional GMS scope for providers that reject com.fido.asm as a privileged WebAuthn caller. */
    fun installForGoogleProvider(param: PackageReadyParam) {
        runtime.attempt("Google Password Manager Hybrid identity compatibility") {
            val requestTypes = listOf(
                "android.service.credentials.BeginCreateCredentialRequest",
                "android.service.credentials.BeginGetCredentialRequest",
            )
            val methods = requestTypes.mapNotNull { className ->
                runCatching {
                    Class.forName(className, false, param.classLoader)
                        .getDeclaredMethod("getCallingAppInfo")
                        .apply { isAccessible = true }
                }.getOrNull()
            }
            if (methods.isEmpty()) error("framework CallingAppInfo accessors not found")

            methods.forEach { method ->
                runtime.hook(method)
                    .intercept { chain ->
                        val rawResult = chain.proceed()
                        val original = rawResult as? CallingAppInfo
                            ?: return@intercept rawResult
                        if (original.packageName != TargetPackage.FIDO || original.origin.isNullOrEmpty()) {
                            original
                        } else {
                            CallingAppInfo(
                                TRUSTED_BROWSER_PACKAGE,
                                original.signingInfo,
                                original.origin,
                            )
                        }
                    }
            }
        }
    }

    private fun hookHybridBoundary(param: PackageReadyParam, bridge: DexKitBridge) {
        // Stable log literals identify LocalStrategy.process without depending on R8 names.
        val boundary = bridge.findMethod {
            findFirst = true
            matcher {
                returnType = "void"
                paramCount = 3
                usingStrings("LocalStrategy", "process request unknown", "process end")
            }
        }.singleOrNull()?.getMethodInstance(param.classLoader)
            ?: error("Hybrid local-strategy boundary not found")

        val callbackMethods = CallbackMethods.from(boundary.parameterTypes[2])
            ?: error("Hybrid callback contract not found")

        runtime.hook(boundary)
            .intercept { chain ->
                val rawRequest = chain.getArg(1) ?: return@intercept chain.proceed()
                val callback = chain.getArg(2) ?: return@intercept chain.proceed()
                val activity = findActivity(chain.getArg(0))
                    ?.takeUnless { it.isFinishing || it.isDestroyed }
                    ?: return@intercept chain.proceed()
                val request = decodeRequest(rawRequest) ?: return@intercept chain.proceed()
                val callbackHandle = HybridCallback(callback, callbackMethods, runtime)

                when (request.kind) {
                    RequestKind.CREATE -> launchCreate(activity, request, callbackHandle)
                    RequestKind.GET -> launchGet(activity, request, callbackHandle)
                }
                null
            }
    }

    private fun decodeRequest(request: Any): HybridRequest? {
        serializers[request.javaClass]?.let { serializer ->
            val cachedResult = runCatching {
                (serializer.invoke(request) as? ByteArray)?.let(::decodeSerializedRequest)
            }.getOrNull()
            if (cachedResult != null) return cachedResult
            serializers.remove(request.javaClass, serializer)
        }

        return allMembers(request.javaClass) { it.declaredMethods }
            .filter {
                !Modifier.isStatic(it.modifiers) &&
                    it.parameterCount == 0 &&
                    it.returnType == ByteArray::class.java
            }
            .firstNotNullOfOrNull { serializer ->
                val result = runCatching {
                    serializer.isAccessible = true
                    (serializer.invoke(request) as? ByteArray)?.let(::decodeSerializedRequest)
                }.getOrNull()
                if (result != null) serializers.putIfAbsent(request.javaClass, serializer)
                result
            }
    }

    private fun decodeSerializedRequest(encoded: ByteArray): HybridRequest? = runCatching {
        val values = CborReader(encoded).readComplete() as? Map<*, *> ?: return null
        when (values.intKey(1)) {
            is ByteArray -> decodeCreateRequest(values)
            is String -> decodeGetRequest(values)
            else -> null
        }
    }.getOrNull()

    private fun decodeCreateRequest(values: Map<*, *>): HybridRequest? {
        val clientDataHash = values.intKey(1) as? ByteArray ?: return null
        val relyingParty = values.intKey(2) as? Map<*, *> ?: return null
        val user = values.intKey(3) as? Map<*, *> ?: return null
        val rpId = relyingParty.stringKey("id") as? String ?: return null
        val userId = user.stringKey("id") as? ByteArray ?: return null
        val userName = user.stringKey("name") as? String ?: return null
        val algorithms = values.intKey(4) as? List<*> ?: return null

        val parameters = JSONArray()
        algorithms.forEach { value ->
            val parameter = value as? Map<*, *> ?: return@forEach
            val algorithm = parameter.stringKey("alg") as? Number ?: return@forEach
            parameters.put(
                JSONObject()
                    .put("type", parameter.stringKey("type") as? String ?: "public-key")
                    .put("alg", algorithm.toInt()),
            )
        }
        if (parameters.length() == 0) return null

        val json = JSONObject()
            .put("challenge", clientDataHash.base64Url())
            .put(
                "rp",
                JSONObject()
                    .put("id", rpId)
                    .put("name", relyingParty.stringKey("name") as? String ?: rpId),
            )
            .put(
                "user",
                JSONObject()
                    .put("id", userId.base64Url())
                    .put("name", userName)
                    .put("displayName", user.stringKey("displayName") as? String ?: userName),
            )
            .put("pubKeyCredParams", parameters)

        (values.intKey(5) as? List<*>)?.toDescriptorArray()?.takeIf { it.length() > 0 }?.let {
            json.put("excludeCredentials", it)
        }
        (values.intKey(7) as? Map<*, *>)?.let { options ->
            val residentKey = options.stringKey("rk") as? Boolean
            val userVerification = options.stringKey("uv") as? Boolean
            if (residentKey != null || userVerification != null) {
                json.put(
                    "authenticatorSelection",
                    JSONObject().apply {
                        residentKey?.let {
                            put("residentKey", if (it) "required" else "discouraged")
                            put("requireResidentKey", it)
                        }
                        userVerification?.let {
                            put("userVerification", if (it) "required" else "discouraged")
                        }
                    },
                )
            }
        }
        json.put("attestation", "none")
        return HybridRequest(RequestKind.CREATE, rpId, clientDataHash, json.toString())
    }

    private fun decodeGetRequest(values: Map<*, *>): HybridRequest? {
        val rpId = values.intKey(1) as? String ?: return null
        val clientDataHash = values.intKey(2) as? ByteArray ?: return null
        val json = JSONObject()
            .put("challenge", clientDataHash.base64Url())
            .put("rpId", rpId)

        (values.intKey(3) as? List<*>)?.toDescriptorArray()?.takeIf { it.length() > 0 }?.let {
            json.put("allowCredentials", it)
        }
        val userVerification = (values.intKey(5) as? Map<*, *>)
            ?.stringKey("uv") as? Boolean
        userVerification?.let {
            json.put("userVerification", if (it) "required" else "discouraged")
        }
        return HybridRequest(RequestKind.GET, rpId, clientDataHash, json.toString())
    }

    private fun List<*>.toDescriptorArray() = JSONArray().also { result ->
        forEach { value ->
            val descriptor = value as? Map<*, *> ?: return@forEach
            val id = descriptor.stringKey("id") as? ByteArray ?: return@forEach
            result.put(
                JSONObject()
                    .put("type", descriptor.stringKey("type") as? String ?: "public-key")
                    .put("id", id.base64Url()),
            )
        }
    }

    private fun launchCreate(
        activity: Activity,
        request: HybridRequest,
        callback: HybridCallback,
    ) {
        val data = publicKeyBundle(CREATE_PUBLIC_KEY_SUBTYPE, request)
        val frameworkRequest = CreateCredentialRequest.Builder(
            PUBLIC_KEY_TYPE,
            data,
            Bundle(data),
        )
            .setAlwaysSendAppInfoToProvider(true)
            .apply { originForRpId(request.rpId)?.let(::setOrigin) }
            .build()
        val manager = activity.getSystemService(CredentialManager::class.java)
            ?: error("CredentialManager unavailable")

        manager.createCredential(
            activity,
            frameworkRequest,
            null as CancellationSignal?,
            activity.mainExecutor,
            object : OutcomeReceiver<CreateCredentialResponse, CreateCredentialException> {
                override fun onResult(result: CreateCredentialResponse) {
                    runCatching {
                        val responseJson = result.data.getString(REGISTRATION_RESPONSE_JSON)
                            ?: error("missing registration response")
                        val attestation = extractAttestationObject(responseJson)
                            ?: error("missing attestation object")
                        callback.success(byteArrayOf(CTAP_SUCCESS) + attestation)
                    }.onFailure(callback::conversionFailure)
                }

                override fun onError(error: CreateCredentialException) {
                    callback.error()
                }
            },
        )
    }

    private fun launchGet(
        activity: Activity,
        request: HybridRequest,
        callback: HybridCallback,
    ) {
        val data = publicKeyBundle(GET_PUBLIC_KEY_SUBTYPE, request)
        val option = CredentialOption.Builder(PUBLIC_KEY_TYPE, data, Bundle(data)).build()
        val frameworkRequest = GetCredentialRequest.Builder(Bundle())
            .setCredentialOptions(listOf(option))
            .setAlwaysSendAppInfoToProvider(true)
            .apply { originForRpId(request.rpId)?.let(::setOrigin) }
            .build()
        val manager = activity.getSystemService(CredentialManager::class.java)
            ?: error("CredentialManager unavailable")

        manager.getCredential(
            activity,
            frameworkRequest,
            null as CancellationSignal?,
            activity.mainExecutor,
            object : OutcomeReceiver<GetCredentialResponse, GetCredentialException> {
                override fun onResult(result: GetCredentialResponse) {
                    runCatching {
                        val responseJson = result.credential.data.getString(AUTHENTICATION_RESPONSE_JSON)
                            ?: error("missing authentication response")
                        callback.success(buildGetAssertionResponse(responseJson))
                    }.onFailure(callback::conversionFailure)
                }

                override fun onError(error: GetCredentialException) {
                    callback.error()
                }
            },
        )
    }

    private fun publicKeyBundle(subtype: String, request: HybridRequest) = Bundle().apply {
        putString(PUBLIC_KEY_SUBTYPE, subtype)
        putString(PUBLIC_KEY_REQUEST_JSON, request.requestJson)
        putByteArray(PUBLIC_KEY_CLIENT_DATA_HASH, request.clientDataHash)
    }

    private fun extractAttestationObject(responseJson: String): ByteArray? {
        val credential = JSONObject(responseJson)
        val encoded = credential.optJSONObject("response")
            ?.optString("attestationObject")
            ?.takeIf(String::isNotEmpty)
            ?: credential.optString("attestationObject").takeIf(String::isNotEmpty)
        return encoded?.decodeBase64Url()?.takeIf(ByteArray::isNotEmpty)
    }

    private fun buildGetAssertionResponse(responseJson: String): ByteArray {
        val credential = JSONObject(responseJson)
        val response = credential.optJSONObject("response") ?: error("missing response object")
        val authenticatorData = response.requiredBase64("authenticatorData")
        val signature = response.requiredBase64("signature")
        val credentialId = credential.optionalBase64("rawId")
            ?: credential.optionalBase64("id")
            ?: error("missing credential id")
        val userHandle = response.optionalBase64("userHandle")

        return CborWriter().apply {
            writeByte(CTAP_SUCCESS.toInt())
            writeMapSize(if (userHandle == null) 3 else 4)
            writeUnsigned(1)
            writeMapSize(2)
            writeText("type")
            writeText("public-key")
            writeText("id")
            writeBytes(credentialId)
            writeUnsigned(2)
            writeBytes(authenticatorData)
            writeUnsigned(3)
            writeBytes(signature)
            if (userHandle != null) {
                writeUnsigned(4)
                writeMapSize(1)
                writeText("id")
                writeBytes(userHandle)
            }
        }.toByteArray()
    }

    private fun JSONObject.requiredBase64(key: String): ByteArray =
        optionalBase64(key) ?: error("missing $key")

    private fun JSONObject.optionalBase64(key: String): ByteArray? =
        optString(key).takeIf { it.isNotEmpty() && it != "null" }?.decodeBase64Url()

    private fun originForRpId(rpId: String): String? {
        val host = rpId.trim().trimEnd('.')
        if (host.isEmpty() || host.any { it == '/' || it == '@' || it.isWhitespace() }) return null
        val local = host.equals("localhost", true) || IPV4.matches(host) || host.startsWith("[")
        return "${if (local) "http" else "https"}://$host"
    }

    private fun findActivity(root: Any?): Activity? {
        if (root == null) return null
        val visited = IdentityHashMap<Any, Boolean>()

        fun inspect(value: Any?, depth: Int): Activity? {
            when (value) {
                null -> return null
                is Activity -> return value
                is WeakReference<*> -> return value.get() as? Activity
            }
            if (depth == 0 || visited.put(value, true) != null) return null
            for (field in allMembers(value.javaClass) { it.declaredFields }) {
                if (Modifier.isStatic(field.modifiers) || field.type.isPrimitive) continue
                val nested = runCatching {
                    field.isAccessible = true
                    field.get(value)
                }.getOrNull()
                inspect(nested, depth - 1)?.let { return it }
            }
            return null
        }

        return inspect(root, 2)
    }

    private fun <T> allMembers(
        type: Class<*>,
        selector: (Class<*>) -> Array<T>,
    ): Sequence<T> = sequence {
        var current: Class<*>? = type
        while (current != null && current != Any::class.java) {
            yieldAll(selector(current).asSequence())
            current = current.superclass
        }
    }

    private fun Map<*, *>.intKey(key: Int): Any? = entries.firstOrNull {
        (it.key as? Number)?.toInt() == key
    }?.value

    private fun Map<*, *>.stringKey(key: String): Any? = entries.firstOrNull {
        it.key == key
    }?.value

    private fun ByteArray.base64Url(): String = Base64.encodeToString(
        this,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

    private fun String.decodeBase64Url(): ByteArray = Base64.decode(
        this,
        Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
    )

    private data class HybridRequest(
        val kind: RequestKind,
        val rpId: String,
        val clientDataHash: ByteArray,
        val requestJson: String,
    )

    private enum class RequestKind { CREATE, GET }

    private data class CallbackMethods(val success: Method, val error: Method) {
        companion object {
            fun from(callbackType: Class<*>): CallbackMethods? {
                val methods = callbackType.methods.asSequence() + callbackType.declaredMethods.asSequence()
                val success = methods.firstOrNull {
                    it.parameterCount == 1 &&
                        it.parameterTypes[0] == ByteArray::class.java &&
                        it.returnType == Void.TYPE
                } ?: return null
                val error = (callbackType.methods.asSequence() + callbackType.declaredMethods.asSequence())
                    .firstOrNull {
                        it.parameterCount == 1 &&
                            it.parameterTypes[0] == Byte::class.javaPrimitiveType &&
                            it.returnType == Void.TYPE
                    } ?: return null
                success.isAccessible = true
                error.isAccessible = true
                return CallbackMethods(success, error)
            }
        }
    }

    private class HybridCallback(
        private val target: Any,
        private val methods: CallbackMethods,
        private val runtime: HookRuntime,
    ) {
        fun success(response: ByteArray) {
            runCatching { methods.success.invoke(target, response) }
                .onFailure { runtime.warning("Hybrid success callback failed", it) }
        }

        fun error() {
            runCatching { methods.error.invoke(target, CTAP_OTHER_ERROR) }
                .onFailure { runtime.warning("Hybrid error callback failed", it) }
        }

        fun conversionFailure(cause: Throwable) {
            runtime.warning("Hybrid provider response conversion failed", cause)
            error()
        }
    }

    /** Definite-length CBOR reader; CTAP requests do not use indefinite containers. */
    private class CborReader(private val bytes: ByteArray) {
        private var position = 0

        fun readComplete(): Any? {
            val value = readValue()
            if (position != bytes.size) error("trailing CBOR data")
            return value
        }

        private fun readValue(): Any? {
            val initial = readByte()
            val major = initial ushr 5
            val info = initial and 0x1f
            return when (major) {
                0 -> readLength(info)
                1 -> -1L - readLength(info)
                2 -> readBytes(readLength(info).checkedSize())
                3 -> String(readBytes(readLength(info).checkedSize()), StandardCharsets.UTF_8)
                4 -> List(readLength(info).checkedSize()) { readValue() }
                5 -> LinkedHashMap<Any?, Any?>().apply {
                    repeat(readLength(info).checkedSize()) { put(readValue(), readValue()) }
                }
                6 -> {
                    readLength(info)
                    readValue()
                }
                7 -> when (info) {
                    20 -> false
                    21 -> true
                    22, 23 -> null
                    else -> error("unsupported CBOR simple value")
                }
                else -> error("unsupported CBOR major type")
            }
        }

        private fun readLength(info: Int): Long = when (info) {
            in 0..23 -> info.toLong()
            24 -> readByte().toLong()
            25 -> readUnsigned(2)
            26 -> readUnsigned(4)
            27 -> readUnsigned(8)
            else -> error("indefinite CBOR value")
        }

        private fun readUnsigned(size: Int): Long {
            var value = 0L
            repeat(size) { value = (value shl 8) or readByte().toLong() }
            return value
        }

        private fun readByte(): Int {
            if (position >= bytes.size) error("truncated CBOR data")
            return bytes[position++].toInt() and 0xff
        }

        private fun readBytes(size: Int): ByteArray {
            if (size < 0 || position + size > bytes.size) error("truncated CBOR value")
            return bytes.copyOfRange(position, position + size).also { position += size }
        }

        private fun Long.checkedSize(): Int {
            if (this !in 0..Int.MAX_VALUE.toLong()) error("CBOR value too large")
            return toInt()
        }
    }

    private class CborWriter {
        private val output = ByteArrayOutputStream()

        fun writeByte(value: Int) = output.write(value)
        fun writeUnsigned(value: Int) = writeTypeAndLength(0, value)
        fun writeMapSize(size: Int) = writeTypeAndLength(5, size)

        fun writeText(value: String) {
            val encoded = value.toByteArray(StandardCharsets.UTF_8)
            writeTypeAndLength(3, encoded.size)
            output.write(encoded)
        }

        fun writeBytes(value: ByteArray) {
            writeTypeAndLength(2, value.size)
            output.write(value)
        }

        fun toByteArray(): ByteArray = output.toByteArray()

        private fun writeTypeAndLength(type: Int, length: Int) {
            require(length >= 0)
            when {
                length < 24 -> output.write((type shl 5) or length)
                length <= 0xff -> {
                    output.write((type shl 5) or 24)
                    output.write(length)
                }
                length <= 0xffff -> {
                    output.write((type shl 5) or 25)
                    output.write(length ushr 8)
                    output.write(length)
                }
                else -> {
                    output.write((type shl 5) or 26)
                    output.write(length ushr 24)
                    output.write(length ushr 16)
                    output.write(length ushr 8)
                    output.write(length)
                }
            }
        }
    }

    private companion object {
        const val TRUSTED_BROWSER_PACKAGE = "com.android.browser"
        const val PUBLIC_KEY_TYPE = "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        const val PUBLIC_KEY_SUBTYPE = "androidx.credentials.BUNDLE_KEY_SUBTYPE"
        const val CREATE_PUBLIC_KEY_SUBTYPE =
            "androidx.credentials.BUNDLE_VALUE_SUBTYPE_CREATE_PUBLIC_KEY_CREDENTIAL_REQUEST"
        const val GET_PUBLIC_KEY_SUBTYPE =
            "androidx.credentials.BUNDLE_VALUE_SUBTYPE_GET_PUBLIC_KEY_CREDENTIAL_OPTION"
        const val PUBLIC_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
        const val PUBLIC_KEY_CLIENT_DATA_HASH =
            "androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH"
        const val REGISTRATION_RESPONSE_JSON =
            "androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON"
        const val AUTHENTICATION_RESPONSE_JSON =
            "androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON"
        const val CTAP_SUCCESS: Byte = 0
        const val CTAP_OTHER_ERROR: Byte = 127
        val IPV4 = Regex("\\d{1,3}(?:\\.\\d{1,3}){3}")
    }
}
