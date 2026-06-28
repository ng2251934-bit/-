package com.securityguard.app.protector

import android.content.Context
import android.util.Base64
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.*
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import java.io.*
import java.security.*
import java.security.cert.X509Certificate
import java.util.jar.Attributes
import java.util.jar.Manifest as JarManifest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * APK 处理器 - 多层加密加固 + 标准签名
 * 加密顺序：SHA256 校验附加 → AES-256-CBC → 自定义Base64 → XOR
 */
object ApkProcessor {

    private const val SHELL_DEX_ASSET = "shell.dex"
    private const val ENCRYPTED_DEX_ENTRY = "classes_encrypted.dex"
    private const val SHELL_APPLICATION_CLASS = "com.securityguard.shell.ProxyApplication"
    private const val AES_KEY_MATERIAL = "SecurityGuard_SecureKey_2024"

    private val CUSTOM_BASE64 = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/=".toCharArray()
    private val STANDARD_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray()

    private val SEED = byteArrayOf(
        0x53, 0x47, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
        0x74, 0x32, 0x30, 0x32, 0x34, 0x21, 0x40, 0x23
    )

    data class ProcessResult(
        val success: Boolean,
        val outputPath: String?,
        val message: String,
        val details: String = ""
    )

    data class ProtectOptions(
        val enableDexEncryption: Boolean = true,
        val encryptionLevel: Int = 3
    )

    data class ProgressUpdate(
        val step: String,
        val progress: Float // 0.0 - 1.0
    )

    fun protectApk(
        context: Context,
        inputApkPath: String,
        outputDir: String,
        options: ProtectOptions,
        onProgress: ((ProgressUpdate) -> Unit)? = null
    ): ProcessResult {
        return try {
            val inputFile = File(inputApkPath)
            val outputName = "protected_${inputFile.nameWithoutExtension}.apk"
            val unsignedFile = File(context.cacheDir, "unsigned_${inputFile.nameWithoutExtension}.apk")
            val outputFile = File(outputDir, outputName)

            val details = StringBuilder()

            // ====== 阶段1: 读取原始 APK ======
            onProgress?.invoke(ProgressUpdate("读取 APK 结构...", 0.05f))
            val zipFile = ZipFile(inputFile)
            val entries = mutableMapOf<String, ByteArray>()
            val entryMethods = mutableMapOf<String, Int>() // 保留压缩方式
            val dexFiles = mutableListOf<String>()

            zipFile.entries().asIterator().forEach { entry ->
                if (!entry.isDirectory && !entry.name.startsWith("META-INF/")) {
                    val data = zipFile.getInputStream(entry).readBytes()
                    entries[entry.name] = data
                    entryMethods[entry.name] = entry.method
                    if (entry.name.endsWith(".dex")) {
                        dexFiles.add(entry.name)
                    }
                }
            }
            zipFile.close()

            // ====== 阶段2: 加密 DEX ======
            if (options.enableDexEncryption) {
                onProgress?.invoke(ProgressUpdate("多层加密 DEX...", 0.15f))

                val originalDex = entries["classes.dex"]
                if (originalDex != null) {
                    val encryptedDex = multiLayerEncrypt(originalDex, options.encryptionLevel)
                    entries["assets/$ENCRYPTED_DEX_ENTRY"] = encryptedDex
                    entryMethods["assets/$ENCRYPTED_DEX_ENTRY"] = ZipEntry.STORED
                    details.appendLine("✓ 主 DEX 已加密 (${originalDex.size / 1024}KB → ${encryptedDex.size / 1024}KB)")
                }

                dexFiles.filter { it != "classes.dex" }.forEach { dexName ->
                    entries[dexName]?.let { dex ->
                        val encryptedMulti = multiLayerEncrypt(dex, options.encryptionLevel)
                        entries["assets/${dexName}_encrypted"] = encryptedMulti
                        entryMethods["assets/${dexName}_encrypted"] = ZipEntry.STORED
                        details.appendLine("✓ $dexName 已加密")
                    }
                    entries.remove(dexName)
                    entryMethods.remove(dexName)
                }

                // ====== 阶段3: 注入 Shell DEX ======
                onProgress?.invoke(ProgressUpdate("注入 Shell DEX...", 0.25f))
                val shellBytes = loadShellDex(context)
                entries["classes.dex"] = shellBytes
                entryMethods["classes.dex"] = ZipEntry.STORED
                details.appendLine("✓ Shell DEX 已注入 (${shellBytes.size / 1024}KB)")

                // ====== 阶段4: 修补 Manifest ======
                onProgress?.invoke(ProgressUpdate("修补 Manifest...", 0.30f))
                val manifestBytes = entries["AndroidManifest.xml"]
                if (manifestBytes != null) {
                    val patchResult = patchBinaryManifest(manifestBytes)
                    entries["AndroidManifest.xml"] = patchResult.patchedBytes
                    details.appendLine("✓ Manifest 已修补 → $SHELL_APPLICATION_CLASS")
                    patchResult.originalAppClass?.let { details.appendLine("  原始: $it") }
                }
            }

            // ====== 阶段5: 打包未签名 APK ======
            onProgress?.invoke(ProgressUpdate("打包 APK...", 0.40f))
            ZipOutputStream(BufferedOutputStream(FileOutputStream(unsignedFile))).use { zos ->
                entries.forEach { (name, data) ->
                    if (data.isNotEmpty()) {
                        val entry = ZipEntry(name)
                        val method = entryMethods[name] ?: ZipEntry.DEFLATED
                        entry.method = method
                        if (method == ZipEntry.STORED) {
                            // STORED 需要预设 size 和 CRC
                            entry.size = data.size.toLong()
                            val crc = CRC32()
                            crc.update(data)
                            entry.crc = crc.value
                        }
                        zos.putNextEntry(entry)
                        zos.write(data)
                        zos.closeEntry()
                    }
                }
            }

            // ====== 阶段6: 加载 Keystore ======
            onProgress?.invoke(ProgressUpdate("加载签名证书...", 0.55f))
            val keystoreFile = File(context.filesDir, "security_guard.keystore")
            if (!keystoreFile.exists()) {
                context.assets.open("security_guard.keystore").use { input ->
                    FileOutputStream(keystoreFile).use { output -> input.copyTo(output) }
                }
            }

            val keystore = KeyStore.getInstance("PKCS12")
            keystore.load(FileInputStream(keystoreFile), "SecurityGuard2024!".toCharArray())
            val privateKey = keystore.getKey("security_guard_key", "SecurityGuard2024!".toCharArray()) as PrivateKey
            val certChain = keystore.getCertificateChain("security_guard_key")
            val cert = certChain[0] as X509Certificate

            // ====== 阶段7: 签名 ======
            onProgress?.invoke(ProgressUpdate("正在签名...", 0.65f))
            signApkWithBouncyCastle(unsignedFile, outputFile, privateKey, cert)

            // 清理
            unsignedFile.delete()

            onProgress?.invoke(ProgressUpdate("完成!", 1.0f))
            details.appendLine("✓ 标准签名完成 (可直接安装)")

            ProcessResult(
                success = true,
                outputPath = outputFile.absolutePath,
                message = "加固完成！可直接安装",
                details = details.toString().trim()
            )
        } catch (e: Exception) {
            ProcessResult(
                success = false,
                outputPath = null,
                message = "加固失败: ${e.message}",
                details = e.stackTraceToString()
            )
        }
    }

    // ==================== 多层加密 ====================
    private fun multiLayerEncrypt(data: ByteArray, level: Int): ByteArray {
        var result = data

        // 最内层：SHA-256 校验值附加
        val md = MessageDigest.getInstance("SHA-256")
        result = result + md.digest(result)

        // AES-256-CBC
        val derivedKey = MessageDigest.getInstance("SHA-256").digest(AES_KEY_MATERIAL.toByteArray())
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derivedKey, "AES"), IvParameterSpec(iv))
        result = iv + cipher.doFinal(result)

        if (level >= 2) {
            val base64 = Base64.encodeToString(result, Base64.NO_WRAP)
            val sb = StringBuilder()
            for (c in base64) {
                val idx = STANDARD_BASE64.indexOf(c)
                sb.append(if (idx >= 0) CUSTOM_BASE64[idx] else c)
            }
            result = sb.toString().toByteArray()
        }

        if (level >= 3) {
            result = xorEncrypt(result, SEED)
        }
        return result
    }

    private fun xorEncrypt(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(data.size) { i -> (data[i].toInt() xor key[i % key.size].toInt()).toByte() }
    }

    // ==================== 二进制 Manifest 修补 ====================
    data class ManifestPatchResult(val patchedBytes: ByteArray, val originalAppClass: String?)

    private fun patchBinaryManifest(manifestBytes: ByteArray): ManifestPatchResult {
        var data = manifestBytes.copyOf()
        var originalAppClass: String? = null

        try {
            val stringPoolOffset = findStringPool(data)
            if (stringPoolOffset < 0) return ManifestPatchResult(data, null)

            val stringCount = readIntLE(data, stringPoolOffset + 8)
            val stringStart = readIntLE(data, stringPoolOffset + 20)
            val offsetsStart = stringPoolOffset + 28
            val stringDataStart = stringPoolOffset + stringStart

            for (i in 0 until stringCount) {
                val offset = readIntLE(data, offsetsStart + i * 4)
                val strPos = stringDataStart + offset
                val (charLen, lenSize) = readStringLen(data, strPos)
                val actualStrStart = strPos + lenSize + 2
                if (actualStrStart + charLen * 2 > data.size) continue

                val str = readUtf16String(data, actualStrStart, charLen)
                if (str.isNotEmpty() && str != SHELL_APPLICATION_CLASS &&
                    str.contains(".") && (str.endsWith("Application") || str.contains(".Application")) &&
                    !str.startsWith("android.") && !str.startsWith("androidx.")) {
                    originalAppClass = str
                    data = replaceStringInBinaryXml(data, stringPoolOffset, str, SHELL_APPLICATION_CLASS)
                    break
                }
            }
        } catch (_: Exception) {}

        return ManifestPatchResult(data, originalAppClass)
    }

    private fun findStringPool(data: ByteArray): Int {
        var offset = 8
        while (offset + 4 <= data.size) {
            val chunkType = readIntLE(data, offset)
            if (chunkType == 0x001C0001) return offset
            val chunkSize = readIntLE(data, offset + 4)
            if (chunkSize <= 0) break
            offset += chunkSize
        }
        return -1
    }

    private fun readStringLen(data: ByteArray, pos: Int): Pair<Int, Int> {
        if (pos + 1 < data.size && (data[pos].toInt() and 0x80) != 0) {
            return (((data[pos].toInt() and 0x7F) shl 8) or (data[pos + 1].toInt() and 0xFF)) to 2
        }
        return (data[pos].toInt() and 0xFF) to 1
    }

    private fun readUtf16String(data: ByteArray, start: Int, charLen: Int): String {
        return buildString {
            for (j in 0 until charLen) {
                val pos = start + j * 2
                if (pos + 1 < data.size) {
                    append(((data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)).toChar())
                }
            }
        }
    }

    private fun replaceStringInBinaryXml(data: ByteArray, stringPoolOffset: Int, oldStr: String, newStr: String): ByteArray {
        val stringCount = readIntLE(data, stringPoolOffset + 8)
        val stringStart = readIntLE(data, stringPoolOffset + 20)
        val offsetsStart = stringPoolOffset + 28
        val stringDataStart = stringPoolOffset + stringStart
        val result = data.copyOf()

        for (i in 0 until stringCount) {
            val offset = readIntLE(result, offsetsStart + i * 4)
            val strPos = stringDataStart + offset
            val (charLen, lenSize) = readStringLen(result, strPos)
            val actualStrStart = strPos + lenSize + 2
            if (actualStrStart + charLen * 2 > result.size) continue

            if (readUtf16String(result, actualStrStart, charLen) == oldStr) {
                val newBytes = newStr.toByteArray(Charsets.UTF_16LE)
                val newCharLen = newStr.length
                if (lenSize == 1) result[strPos] = (newCharLen and 0xFF).toByte()
                else {
                    result[strPos] = (0x80 or ((newCharLen shr 8) and 0x7F)).toByte()
                    result[strPos + 1] = (newCharLen and 0xFF).toByte()
                }
                for (j in 0 until maxOf(newCharLen * 2, charLen * 2)) {
                    val pos = actualStrStart + j
                    if (pos < result.size) result[pos] = if (j < newBytes.size) newBytes[j] else 0
                }
                break
            }
        }
        return result
    }

    private fun readIntLE(data: ByteArray, offset: Int): Int {
        if (offset + 4 > data.size) return 0
        return (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8) or
               ((data[offset + 2].toInt() and 0xFF) shl 16) or ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    // ==================== 标准签名：BouncyCastle PKCS7 ====================
    private fun signApkWithBouncyCastle(
        unsignedApk: File,
        signedApk: File,
        privateKey: PrivateKey,
        cert: X509Certificate
    ) {
        // 1. 读取所有文件，计算摘要
        val digestMap = LinkedHashMap<String, ByteArray>()
        val fileData = LinkedHashMap<String, ByteArray>()

        ZipFile(unsignedApk).use { zip ->
            zip.entries().asIterator().forEach { entry ->
                if (!entry.isDirectory && !entry.name.startsWith("META-INF/")) {
                    val data = zip.getInputStream(entry).readBytes()
                    fileData[entry.name] = data
                    val md = MessageDigest.getInstance("SHA-256")
                    digestMap[entry.name] = md.digest(data)
                }
            }
        }

        // 2. 生成 MANIFEST.MF
        val manifest = JarManifest()
        manifest.mainAttributes.apply {
            putValue("Manifest-Version", "1.0")
            putValue("Created-By", "SecurityGuard APK Protector")
        }
        for ((name, digest) in digestMap) {
            val attr = Attributes()
            attr.putValue("SHA-256-Digest", Base64.encodeToString(digest, Base64.NO_WRAP))
            manifest.entries[name] = attr
        }
        val manifestBytes = ByteArrayOutputStream().also { manifest.write(it) }.toByteArray()

        // 3. 生成 CERT.SF
        val sfContent = buildString {
            appendLine("Signature-Version: 1.0")
            appendLine("SHA-256-Digest-Manifest: ${Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(manifestBytes), Base64.NO_WRAP)}")
            appendLine("Created-By: SecurityGuard APK Protector")
            appendLine()
            for ((name, digest) in digestMap) {
                val md = MessageDigest.getInstance("SHA-256")
                val entryHeader = "Name: $name\r\n"
                val entryDigestLine = "SHA-256-Digest: ${Base64.encodeToString(digest, Base64.NO_WRAP)}\r\n\r\n"
                val entryHash = md.digest((entryHeader + entryDigestLine).toByteArray())
                appendLine("Name: $name")
                appendLine("SHA-256-Digest: ${Base64.encodeToString(entryHash, Base64.NO_WRAP)}")
                appendLine()
            }
        }
        val sfBytes = sfContent.toByteArray()

        // 4. 使用 BouncyCastle 生成标准 PKCS7 签名
        val certList: MutableList<X509Certificate> = ArrayList()
        certList.add(cert)
        val certStore = JcaCertStore(certList)

        val digestCalculatorProvider = JcaDigestCalculatorProviderBuilder().build()
        val signerInfoGenerator = JcaSignerInfoGeneratorBuilder(digestCalculatorProvider)
            .build(JcaContentSignerBuilder("SHA256withRSA").build(privateKey), cert)

        val generator = CMSSignedDataGenerator()
        generator.addSignerInfoGenerator(signerInfoGenerator)
        generator.addCertificates(certStore)

        val signedData = generator.generate(CMSProcessableByteArray(sfBytes), true)
        val pkcs7Bytes = signedData.encoded

        // 5. 写入签名后的 APK (ZipOutputStream, 不用 JarOutputStream 避免重复 MANIFEST.MF)
        ZipOutputStream(BufferedOutputStream(FileOutputStream(signedApk))).use { out ->
            for ((name, data) in fileData) {
                out.putNextEntry(ZipEntry(name))
                out.write(data)
                out.closeEntry()
            }
            out.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            out.write(manifestBytes)
            out.closeEntry()
            out.putNextEntry(ZipEntry("META-INF/CERT.SF"))
            out.write(sfBytes)
            out.closeEntry()
            out.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            out.write(pkcs7Bytes)
            out.closeEntry()
        }
    }

    // ==================== 工具方法 ====================
    private fun loadShellDex(context: Context): ByteArray {
        return context.assets.open(SHELL_DEX_ASSET).readBytes()
    }

    fun getApkInfo(apkPath: String): Map<String, String> {
        return try {
            val file = File(apkPath)
            val info = mutableMapOf<String, String>()
            info["文件名"] = file.name
            info["大小"] = "%.1f MB".format(file.length() / 1024.0 / 1024.0)
            val zip = ZipFile(file)
            var dexCount = 0
            var dexSize = 0L
            zip.entries().asIterator().forEach { entry ->
                if (entry.name.endsWith(".dex")) { dexCount++; dexSize += entry.size }
            }
            info["DEX 数量"] = "$dexCount 个"
            info["DEX 总大小"] = "%.1f KB".format(dexSize / 1024.0)
            info["条目总数"] = "${zip.size()}"
            zip.close()
            info
        } catch (e: Exception) {
            mapOf("错误" to (e.message ?: "未知"))
        }
    }
}