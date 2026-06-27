package com.securityguard.app.protector

import android.content.Context
import android.util.Base64
import java.io.*
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * APK 处理器 - 多层加密加固
 * 加密顺序：SHA256 校验 → AES-256-CBC → 自定义 Base64 → XOR
 * 解密顺序：XOR → 自定义 Base64 → AES-256-CBC → SHA256 校验
 */
object ApkProcessor {

    private const val SHELL_DEX_ASSET = "shell.dex"
    private const val ENCRYPTED_DEX_ENTRY = "classes_encrypted.dex"

    // 自定义 Base64 映射表 (与 shell 相同)
    private val CUSTOM_BASE64 = 
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/=".toCharArray()

    private val STANDARD_BASE64 = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray()

    // 种子密钥
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
        val encryptionLevel: Int = 3  // 1=基础, 2=标准, 3=深度
    )

    /**
     * 加固 APK
     */
    fun protectApk(
        context: Context,
        inputApkPath: String,
        outputDir: String,
        options: ProtectOptions
    ): ProcessResult {
        return try {
            val inputFile = File(inputApkPath)
            val outputName = "protected_${inputFile.nameWithoutExtension}.apk"
            val outputFile = File(outputDir, outputName)

            // 读取原始 APK
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

            if (options.enableDexEncryption) {
                // 处理主 DEX
                val originalDex = entries["classes.dex"]
                if (originalDex != null) {
                    // 多层加密
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
            }

            // 修改 AndroidManifest
            entries["AndroidManifest.xml"] = entries["AndroidManifest.xml"] ?: ByteArray(0)

            // 打包
            ZipOutputStream(BufferedOutputStream(FileOutputStream(outputFile))).use { zos ->
                entries.forEach { (name, data) ->
                    if (data.isNotEmpty()) {
                        zos.putNextEntry(ZipEntry(name))
                        zos.write(data)
                        zos.closeEntry()
                    }
                }
            }

            ProcessResult(
                success = true,
                outputPath = outputFile.absolutePath,
                message = "加固完成！",
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
     * 多层加密：SHA256 → AES-256-CBC → Base64 → XOR
     */
    private fun multiLayerEncrypt(data: ByteArray, level: Int): ByteArray {
        var result = data

        // 第四层（先）：SHA-256 校验值附加
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(result)
        result = result + hash

        // 第三层：AES-256-CBC 加密
        val aesKey = ByteArray(32)
        SecureRandom().nextBytes(aesKey)
        // 使用固定派生密钥（与 shell 解密匹配）
        val derivedKey = MessageDigest.getInstance("SHA-256").digest(
            "SecurityGuard_SecureKey_2024".toByteArray()
        )
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

    private fun loadShellDex(context: Context): ByteArray {
        return context.assets.open(SHELL_DEX_ASSET).readBytes()
    }

    /**
     * 获取 APK 信息
     */
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