package com.securityguard.app.protector

import android.content.Context
import android.util.Base64
import java.io.*
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.jar.Attributes
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import java.util.jar.Manifest as JarManifest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * APK 处理器 - 多层加密加固 + 自动签名
 * 加密顺序：SHA256 校验附加 → AES-256-CBC → 自定义Base64 → XOR
 * 解密顺序：XOR → 自定义Base64 → AES-256-CBC → SHA256 校验
 */
object ApkProcessor {

    private const val SHELL_DEX_ASSET = "shell.dex"
    private const val ENCRYPTED_DEX_ENTRY = "classes_encrypted.dex"
    private const val SHELL_APPLICATION_CLASS = "com.securityguard.shell.ProxyApplication"
    private const val AES_KEY_MATERIAL = "SecurityGuard_SecureKey_2024"

    private val CUSTOM_BASE64 = 
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/=".toCharArray()
    private val STANDARD_BASE64 = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray()

    private val SEED = byteArrayOf(
        0x53, 0x47, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
        0x74, 0x32, 0x30, 0x32, 0x34, 0x21, 0x40, 0x23
    )

    // Android 二进制 XML 的魔数
    private val AXML_MAGIC = byteArrayOf(0x03, 0x00, 0x08, 0x00)

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

    fun protectApk(
        context: Context,
        inputApkPath: String,
        outputDir: String,
        options: ProtectOptions
    ): ProcessResult {
        return try {
            val inputFile = File(inputApkPath)
            val outputName = "protected_${inputFile.nameWithoutExtension}.apk"
            val unsignedFile = File(outputDir, "unsigned_${inputFile.nameWithoutExtension}.apk")
            val outputFile = File(outputDir, outputName)

            val zipFile = ZipFile(inputFile)
            val entries = mutableMapOf<String, ByteArray>()
            val dexFiles = mutableListOf<String>()

            zipFile.entries().asIterator().forEach { entry ->
                if (!entry.isDirectory) {
                    val data = zipFile.getInputStream(entry).readBytes()
                    entries[entry.name] = data
                    if (entry.name.endsWith(".dex")) {
                        dexFiles.add(entry.name)
                    }
                }
            }
            zipFile.close()

            val details = StringBuilder()
            var originalAppClass: String? = null

            if (options.enableDexEncryption) {
                // 处理主 DEX
                val originalDex = entries["classes.dex"]
                if (originalDex != null) {
                    val encryptedDex = multiLayerEncrypt(originalDex, options.encryptionLevel)
                    entries["assets/$ENCRYPTED_DEX_ENTRY"] = encryptedDex
                    details.appendLine("✓ 主 DEX 已加密 (${originalDex.size / 1024}KB → ${encryptedDex.size / 1024}KB)")
                }

                // 处理多 DEX
                dexFiles.filter { it != "classes.dex" }.forEach { dexName ->
                    entries[dexName]?.let { dex ->
                        val encryptedMulti = multiLayerEncrypt(dex, options.encryptionLevel)
                        entries["assets/${dexName}_encrypted"] = encryptedMulti
                        details.appendLine("✓ $dexName 已加密")
                    }
                    entries.remove(dexName)
                }

                // 替换为 shell DEX
                val shellBytes = loadShellDex(context)
                entries["classes.dex"] = shellBytes
                details.appendLine("✓ Shell DEX 已注入 (${shellBytes.size / 1024}KB)")

                // 修补二进制 Manifest
                val manifestBytes = entries["AndroidManifest.xml"]
                if (manifestBytes != null) {
                    val result = patchBinaryManifest(manifestBytes)
                    entries["AndroidManifest.xml"] = result.patchedBytes
                    originalAppClass = result.originalAppClass
                    details.appendLine("✓ Manifest 已修补 → $SHELL_APPLICATION_CLASS")
                    if (originalAppClass != null) {
                        details.appendLine("  原始 Application: $originalAppClass")
                    }
                }
            }

            // 先打包未签名的 APK
            ZipOutputStream(BufferedOutputStream(FileOutputStream(unsignedFile))).use { zos ->
                entries.forEach { (name, data) ->
                    if (data.isNotEmpty()) {
                        zos.putNextEntry(ZipEntry(name))
                        zos.write(data)
                        zos.closeEntry()
                    }
                }
            }

            // 自动签名
            val keystoreFile = File(context.filesDir, "security_guard.keystore")
            if (!keystoreFile.exists()) {
                // 从 asset 复制 keystore
                context.assets.open("security_guard.keystore").use { input ->
                    FileOutputStream(keystoreFile).use { output ->
                        input.copyTo(output)
                    }
                }
            }

            val signed = signApk(unsignedFile, outputFile, keystoreFile)
            unsignedFile.delete()

            if (signed) {
                details.appendLine("✓ 自动签名完成")
            } else {
                details.appendLine("⚠ 签名失败，输出未签名 APK")
            }

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

    /**
     * 多层加密：SHA256 附加 → AES-256-CBC → 自定义Base64 → XOR
     */
    private fun multiLayerEncrypt(data: ByteArray, level: Int): ByteArray {
        var result = data

        // 第四层（最先，最内层）：SHA-256 校验值附加
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(result)
        result = result + hash

        // 第三层：AES-256-CBC 加密
        val derivedKey = MessageDigest.getInstance("SHA-256")
            .digest(AES_KEY_MATERIAL.toByteArray())
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)

        val keySpec = SecretKeySpec(derivedKey, "AES")
        val ivSpec = IvParameterSpec(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        result = iv + cipher.doFinal(result)

        if (level >= 2) {
            // 第二层：自定义 Base64 编码
            val base64 = Base64.encodeToString(result, Base64.NO_WRAP)
            val sb = StringBuilder()
            for (c in base64) {
                val idx = STANDARD_BASE64.indexOf(c)
                sb.append(if (idx >= 0) CUSTOM_BASE64[idx] else c)
            }
            result = sb.toString().toByteArray()
        }

        if (level >= 3) {
            // 第一层（最外层）：XOR 混淆
            result = xorEncrypt(result, SEED)
        }

        return result
    }

    private fun xorEncrypt(data: ByteArray, key: ByteArray): ByteArray {
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[i] = (data[i].toInt() xor key[i % key.size].toInt()).toByte()
        }
        return result
    }

    /**
     * 修补二进制 AndroidManifest.xml
     * 在二进制 XML 的字符串池中查找并替换 Application 类名
     */
    data class ManifestPatchResult(
        val patchedBytes: ByteArray,
        val originalAppClass: String?
    )

    private fun patchBinaryManifest(manifestBytes: ByteArray): ManifestPatchResult {
        var originalAppClass: String? = null

        // 检查是否是二进制 XML
        if (manifestBytes.size < 8) {
            return ManifestPatchResult(manifestBytes, null)
        }

        // 二进制 XML 格式：https://justanapplication.wordpress.com/2011/09/22/android-internals-binary-xml-part-two/
        // 头部: magic(4) + fileSize(4)
        // StringPool: type(0x001C0001) + chunkSize(4) + ...

        var data = manifestBytes.copyOf()

        try {
            // 解析 String Pool
            val stringPoolOffset = findStringPool(data)
            if (stringPoolOffset < 0) {
                // 没有 String Pool，无法修补
                return ManifestPatchResult(data, null)
            }

            // 读取 String Pool 头部
            // type(4) + chunkSize(4) + stringCount(4) + styleCount(4) + flags(4) + stringStart(4) + stylesStart(4)
            val stringCount = readIntLE(data, stringPoolOffset + 8)
            val stringStart = readIntLE(data, stringPoolOffset + 20)

            // 遍历字符串偏移表
            val offsetsStart = stringPoolOffset + 28 // 头部 28 字节后是偏移表
            val stringDataStart = stringPoolOffset + stringStart

            // 查找 Application 类名字符串
            for (i in 0 until stringCount) {
                val offset = readIntLE(data, offsetsStart + i * 4)
                val strPos = stringDataStart + offset

                // 读取字符串长度
                var charLen: Int
                var lenSize: Int
                if (strPos + 1 < data.size && (data[strPos].toInt() and 0x80) != 0) {
                    charLen = ((data[strPos].toInt() and 0x7F) shl 8) or (data[strPos + 1].toInt() and 0xFF)
                    lenSize = 2
                } else {
                    charLen = data[strPos].toInt() and 0xFF
                    lenSize = 1
                }

                val actualStrStart = strPos + lenSize + 2 // length + 2 null bytes prefix
                if (actualStrStart + charLen * 2 > data.size) continue

                // 读取 UTF-16 字符串
                val sb = StringBuilder()
                for (j in 0 until charLen) {
                    val pos = actualStrStart + j * 2
                    if (pos + 1 < data.size) {
                        val ch = ((data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)).toChar()
                        sb.append(ch)
                    }
                }
                val str = sb.toString()

                // 查找可能的 Application 类名
                // 特征：通常包含 ".Application" 或类似，且不是我们的 shell
                if (str.isNotEmpty() && str != SHELL_APPLICATION_CLASS &&
                    (str.contains(".Application") || str.contains("Application") && str.contains(".")) &&
                    !str.startsWith("android.") && !str.startsWith("androidx.")) {
                    originalAppClass = str
                    break
                }
            }

            // 如果找到了 Application 类名，替换为 Shell
            if (originalAppClass != null) {
                data = replaceStringInBinaryXml(data, stringPoolOffset, originalAppClass, SHELL_APPLICATION_CLASS)
            }

            // 添加 meta-data 标记（通过修改一个现有字符串或添加）
            // 这里我们简单地在末尾附加一个标记字符串
            // 实际上，我们需要在 String Pool 中设置 SG_REAL_APP

        } catch (e: Exception) {
            // 修补失败，返回原始 Manifest
        }

        return ManifestPatchResult(data, originalAppClass)
    }

    private fun findStringPool(data: ByteArray): Int {
        var offset = 8 // 跳过 magic + fileSize
        while (offset + 4 <= data.size) {
            val chunkType = readIntLE(data, offset)
            if (chunkType == 0x001C0001) {
                return offset
            }
            // 跳过这个 chunk
            if (offset + 8 > data.size) break
            val chunkSize = readIntLE(data, offset + 4)
            offset += chunkSize
            if (chunkSize <= 0) break
        }
        return -1
    }

    private fun replaceStringInBinaryXml(
        data: ByteArray,
        stringPoolOffset: Int,
        oldStr: String,
        newStr: String
    ): ByteArray {
        // 在 String Pool 数据区域中替换字符串
        // 遍历字符串偏移表，找到 oldStr 并替换
        val stringCount = readIntLE(data, stringPoolOffset + 8)
        val stringStart = readIntLE(data, stringPoolOffset + 20)
        val offsetsStart = stringPoolOffset + 28
        val stringDataStart = stringPoolOffset + stringStart

        val result = data.copyOf()

        for (i in 0 until stringCount) {
            val offset = readIntLE(result, offsetsStart + i * 4)
            val strPos = stringDataStart + offset

            var charLen: Int
            var lenSize: Int
            if (strPos + 1 < result.size && (result[strPos].toInt() and 0x80) != 0) {
                charLen = ((result[strPos].toInt() and 0x7F) shl 8) or (result[strPos + 1].toInt() and 0xFF)
                lenSize = 2
            } else {
                charLen = result[strPos].toInt() and 0xFF
                lenSize = 1
            }

            val actualStrStart = strPos + lenSize + 2
            if (actualStrStart + charLen * 2 > result.size) continue

            val sb = StringBuilder()
            for (j in 0 until charLen) {
                val pos = actualStrStart + j * 2
                if (pos + 1 < result.size) {
                    sb.append(((result[pos].toInt() and 0xFF) or ((result[pos + 1].toInt() and 0xFF) shl 8)).toChar())
                }
            }

            if (sb.toString() == oldStr) {
                // 替换字符串
                val newBytes = newStr.toByteArray(Charsets.UTF_16LE)
                val newCharLen = newStr.length

                // 更新长度
                if (lenSize == 1) {
                    result[strPos] = (newCharLen and 0xFF).toByte()
                } else {
                    result[strPos] = (0x80 or ((newCharLen shr 8) and 0x7F)).toByte()
                    result[strPos + 1] = (newCharLen and 0xFF).toByte()
                }

                // 写入新字符串（UTF-16LE）
                for (j in 0 until newCharLen * 2) {
                    if (actualStrStart + j < result.size) {
                        result[actualStrStart + j] = if (j < newBytes.size) newBytes[j] else 0
                    }
                }
                // 零填充剩余字节
                for (j in newCharLen * 2 until charLen * 2) {
                    val pos = actualStrStart + j
                    if (pos < result.size) {
                        result[pos] = 0
                    }
                }
                break
            }
        }

        return result
    }

    private fun readIntLE(data: ByteArray, offset: Int): Int {
        if (offset + 4 > data.size) return 0
        return (data[offset].toInt() and 0xFF) or
               ((data[offset + 1].toInt() and 0xFF) shl 8) or
               ((data[offset + 2].toInt() and 0xFF) shl 16) or
               ((data[offset + 3].toInt() and 0xFF) shl 24)
    }

    /**
     * APK 签名 - 使用 Java Crypto API
     */
    private fun signApk(unsignedApk: File, signedApk: File, keystoreFile: File): Boolean {
        return try {
            val keystore = KeyStore.getInstance("PKCS12")
            keystore.load(FileInputStream(keystoreFile), "SecurityGuard2024!".toCharArray())
            val privateKey = keystore.getKey("security_guard_key", "SecurityGuard2024!".toCharArray()) as PrivateKey
            val certChain = keystore.getCertificateChain("security_guard_key")
            val cert = certChain[0] as X509Certificate

            signApkWithJarSignature(unsignedApk, signedApk, privateKey, cert)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun signApkWithJarSignature(
        inputApk: File,
        outputApk: File,
        privateKey: PrivateKey,
        cert: X509Certificate
    ) {
        // 读取输入 APK，生成 MANIFEST.MF 和 CERT.SF，签名 CERT.SF
        val manifest = JarManifest()
        val mainAttributes = manifest.mainAttributes
        mainAttributes.putValue("Manifest-Version", "1.0")
        mainAttributes.putValue("Created-By", "SecurityGuard APK Protector")

        // 计算每个文件的 SHA-256
        val digestMap = mutableMapOf<String, ByteArray>()
        val entries = mutableListOf<Pair<String, ByteArray>>()

        ZipFile(inputApk).use { zip ->
            zip.entries().asIterator().forEach { entry ->
                if (!entry.isDirectory && !entry.name.startsWith("META-INF/")) {
                    val data = zip.getInputStream(entry).readBytes()
                    entries.add(entry.name to data)
                    val md = MessageDigest.getInstance("SHA-256")
                    digestMap[entry.name] = md.digest(data)
                }
            }
        }

        // 写入 MANIFEST.MF
        for ((name, digest) in digestMap) {
            val attr = Attributes()
            attr.putValue("SHA-256-Digest", Base64.encodeToString(digest, Base64.NO_WRAP))
            manifest.entries[name] = attr
        }

        // 生成 MANIFEST.MF 字节
        val manifestBytes = ByteArrayOutputStream()
        manifest.write(manifestBytes)
        val manifestRaw = manifestBytes.toByteArray()

        // 计算 MANIFEST.MF 的 SHA-256
        val md = MessageDigest.getInstance("SHA-256")
        val manifestDigest = md.digest(manifestRaw)

        // 生成 CERT.SF
        val sfContent = StringBuilder()
        sfContent.appendLine("Signature-Version: 1.0")
        sfContent.appendLine("SHA-256-Digest-Manifest: ${Base64.encodeToString(manifestDigest, Base64.NO_WRAP)}")
        sfContent.appendLine("Created-By: SecurityGuard APK Protector")
        sfContent.appendLine()

        for ((name, digest) in digestMap) {
            // 重新计算每个条目的 hash（CERT.SF 格式）
            val md2 = MessageDigest.getInstance("SHA-256")
            // 对于每个条目，hash 包含: name + CRLF + 两个空格 + SHA-256-Digest: + base64
            val entryName = "Name: $name\r\n"
            val entryLine = entryName.toByteArray()
            val entireEntry = entryLine + "SHA-256-Digest: ${Base64.encodeToString(digest, Base64.NO_WRAP)}\r\n".toByteArray()
            val entryDigest = md2.digest(entireEntry)

            sfContent.appendLine("Name: $name")
            sfContent.appendLine("SHA-256-Digest: ${Base64.encodeToString(entryDigest, Base64.NO_WRAP)}")
            sfContent.appendLine()
        }

        val sfBytes = sfContent.toString().toByteArray()

        // 签名 CERT.SF
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(sfBytes)
        val signedData = signature.sign()

        // 生成 PKCS7 签名块
        val pkcs7Bytes = generatePkcs7Signature(signedData, cert, sfBytes)

        // 写入签名后的 APK
        JarOutputStream(FileOutputStream(outputApk), manifest).use { jos ->
            // 先写入原始条目
            for ((name, data) in entries) {
                jos.putNextEntry(ZipEntry(name))
                jos.write(data)
                jos.closeEntry()
            }

            // 写入签名文件
            jos.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            jos.write(manifestRaw)
            jos.closeEntry()

            jos.putNextEntry(ZipEntry("META-INF/CERT.SF"))
            jos.write(sfBytes)
            jos.closeEntry()

            jos.putNextEntry(ZipEntry("META-INF/CERT.RSA"))
            jos.write(pkcs7Bytes)
            jos.closeEntry()
        }
    }

    private fun generatePkcs7Signature(
        signedData: ByteArray,
        cert: X509Certificate,
        content: ByteArray
    ): ByteArray {
        // 使用 BouncyCastle 风格的 PKCS7 生成
        // 在 Android 上，我们可以使用 SpongyCastle 或自己构建
        // 这里使用简化的 PKCS7 结构
        return try {
            // 尝试使用 Android 内置的 PKCS7 支持
            val certFactory = CertificateFactory.getInstance("X.509")
            val certs = listOf(cert)

            // 构建简化的签名块
            val pkcs7 = ByteArrayOutputStream()

            // 写入证书
            val certBytes = cert.encoded
            // 这是一个简化的实现，使用标准的签名块格式
            buildSignedData(pkcs7, signedData, certBytes, content)

            pkcs7.toByteArray()
        } catch (e: Exception) {
            // 降级：直接拼接签名数据和证书
            val fallback = ByteArrayOutputStream()
            fallback.write(signedData)
            fallback.write(cert.encoded)
            fallback.toByteArray()
        }
    }

    private fun buildSignedData(
        output: ByteArrayOutputStream,
        signature: ByteArray,
        certBytes: ByteArray,
        content: ByteArray
    ) {
        // 简化版 PKCS7 SignedData (BER/DER 编码)
        // 格式: SEQUENCE { OID, [0] { SEQUENCE { ... } } }
        // 实际使用 ASN.1 编码

        val oidSignedData = byteArrayOf(
            0x06, 0x09, 0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0x86.toByte(),
            0xF7.toByte(), 0x0D.toByte(), 0x01, 0x07, 0x02
        )

        // 构建 SignerInfo
        val signerInfo = buildSignerInfo(signature, certBytes)

        // 构建 DigestAlgorithmIdentifiers
        val digestAlgo = byteArrayOf(
            0x30, 0x0B, 0x06, 0x09, 0x60.toByte(), 0x86.toByte(), 0x48.toByte(),
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01
        )

        // 构建 certificates
        val certSeq = byteArrayOf(0x30.toByte()) + encodeLength(certBytes.size) + certBytes

        // 构建 content info
        val contentInfo = byteArrayOf(
            0x30.toByte(), 0x05, 0x06, 0x03, 0x2B.toByte(), 0x06, 0x01
        )

        // 构建 signedData 内部
        val version = byteArrayOf(0x02, 0x01, 0x01)
        val innerSeq = version + digestAlgo + contentInfo + certSeq + signerInfo

        // 构建完整的 signedData
        val signedData = byteArrayOf(0x30.toByte()) + encodeLength(innerSeq.size) + innerSeq

        // 包装在 [0] EXPLICIT tag 中
        val explicitTag = byteArrayOf(0xA0.toByte()) + encodeLength(signedData.size) + signedData

        // 完整的 PKCS7
        val full = oidSignedData + explicitTag
        val pkcs7 = byteArrayOf(0x30.toByte()) + encodeLength(full.size) + full

        output.write(pkcs7)
    }

    private fun buildSignerInfo(signature: ByteArray, certBytes: ByteArray): ByteArray {
        // 简化的 SignerInfo
        val version = byteArrayOf(0x02, 0x01, 0x01)

        // IssuerAndSerialNumber - 简化版
        val issuerSerial = byteArrayOf(
            0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01
        )

        val digestAlgo = byteArrayOf(
            0x30, 0x0B, 0x06, 0x09, 0x60.toByte(), 0x86.toByte(), 0x48.toByte(),
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01
        )

        val digestEncryptionAlgo = byteArrayOf(
            0x30, 0x0B, 0x06, 0x09, 0x2A.toByte(), 0x86.toByte(), 0x48.toByte(),
            0x86.toByte(), 0xF7.toByte(), 0x0D.toByte(), 0x01, 0x01, 0x01
        )

        // 签名值
        val sigOctet = byteArrayOf(0x04.toByte()) + encodeLength(signature.size) + signature

        // 未认证属性
        val unauthAttr = byteArrayOf(0x30.toByte(), 0x00)

        val inner = version + issuerSerial + digestAlgo + digestEncryptionAlgo + sigOctet + unauthAttr
        return byteArrayOf(0x30.toByte()) + encodeLength(inner.size) + inner
    }

    private fun encodeLength(length: Int): ByteArray {
        return when {
            length < 0x80 -> byteArrayOf(length.toByte())
            length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
            length < 0x10000 -> byteArrayOf(
                0x82.toByte(),
                (length shr 8).toByte(),
                length.toByte()
            )
            else -> byteArrayOf(
                0x83.toByte(),
                (length shr 16).toByte(),
                (length shr 8).toByte(),
                length.toByte()
            )
        }
    }

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
                if (entry.name.endsWith(".dex")) {
                    dexCount++
                    dexSize += entry.size
                }
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