package com.securityguard.app.protector

import android.content.Context
import android.util.Base64
import com.wind.meditor.core.FileProcesser
import com.wind.meditor.property.AttributeItem
import com.wind.meditor.property.ModificationProperty
import com.wind.meditor.utils.NodeValue
import net.lingala.zip4j.ZipFile
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.CompressionMethod
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
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * APK 加固处理器 - 基于 dpt-shell 成熟方案
 * 核心组件：
 * - ManifestEditor (WindySha) → 二进制 XML 编辑
 * - zip4j → 专业 ZIP 处理
 * - BouncyCastle → 标准 PKCS7 签名
 */
object ApkProcessor {

    private const val SHELL_DEX_ASSET = "shell.dex"
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

    data class ProgressUpdate(val step: String, val progress: Float)

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
            val outputFile = File(outputDir, outputName)
            val details = StringBuilder()

            // 工作目录
            val workDir = File(context.cacheDir, "apk_work_${System.currentTimeMillis()}")
            val unpackDir = File(workDir, "unpacked")
            unpackDir.mkdirs()

            // ====== 阶段1: 解压 APK (zip4j) ======
            onProgress?.invoke(ProgressUpdate("解压 APK...", 0.05f))
            ZipFile(inputFile).use { zip -> zip.extractAll(unpackDir.absolutePath) }

            // ====== 阶段2: DEX 加密 ======
            if (options.enableDexEncryption) {
                onProgress?.invoke(ProgressUpdate("加密 DEX 文件...", 0.15f))

                val dexFiles = unpackDir.listFiles { f -> f.name.endsWith(".dex") } ?: emptyArray()
                var dexIdx = 0
                for (dexFile in dexFiles) {
                    dexIdx++
                    onProgress?.invoke(ProgressUpdate("加密 DEX ($dexIdx/${dexFiles.size})...", 0.15f + 0.1f * dexIdx / dexFiles.size))

                    val originalDex = dexFile.readBytes()
                    val encryptedDex = multiLayerEncrypt(originalDex, options.encryptionLevel)
                    val encName = if (dexFile.name == "classes.dex") "classes_encrypted.dex"
                        else "${dexFile.nameWithoutExtension}_encrypted.dex"
                    File(unpackDir, "assets").mkdirs()
                    File(unpackDir, "assets/$encName").writeBytes(encryptedDex)
                    details.appendLine("✓ ${dexFile.name} 已加密 (${originalDex.size / 1024}KB → ${encryptedDex.size / 1024}KB)")
                    dexFile.delete()
                }

                // ====== 阶段3: 注入 Shell DEX ======
                onProgress?.invoke(ProgressUpdate("注入 Shell DEX...", 0.30f))
                val shellBytes = loadShellDex(context)
                File(unpackDir, "classes.dex").writeBytes(shellBytes)
                details.appendLine("✓ Shell DEX 已注入 (${shellBytes.size / 1024}KB)")

                // ====== 阶段4: ManifestEditor 修补 Manifest ======
                onProgress?.invoke(ProgressUpdate("修补 Manifest...", 0.35f))
                val manifestFile = File(unpackDir, "AndroidManifest.xml")
                if (manifestFile.exists()) {
                    val manifestDir = File(workDir, "manifest")
                    manifestDir.mkdirs()
                    val patchedManifest = File(manifestDir, "AndroidManifest.xml")

                    val property = ModificationProperty()
                    property.addApplicationAttribute(AttributeItem(NodeValue.Application.NAME, SHELL_APPLICATION_CLASS))
                    FileProcesser.processManifestFile(manifestFile.absolutePath, patchedManifest.absolutePath, property)

                    patchedManifest.copyTo(manifestFile, overwrite = true)
                    details.appendLine("✓ Manifest 已修补 → $SHELL_APPLICATION_CLASS")
                }
            }

            // ====== 阶段5: 重新打包 ======
            onProgress?.invoke(ProgressUpdate("重新打包...", 0.45f))
            val unsignedFile = File(workDir, "unsigned.apk")
            java.util.zip.ZipOutputStream(BufferedOutputStream(FileOutputStream(unsignedFile))).use { zos ->
                unpackDir.walkTopDown().filter { it.isFile }.forEach { file ->
                    val relativePath = file.relativeTo(unpackDir).path.replace("\\", "/")
                    if (!relativePath.startsWith("META-INF/")) {
                        zos.putNextEntry(java.util.zip.ZipEntry(relativePath))
                        zos.write(file.readBytes())
                        zos.closeEntry()
                    }
                }
            }

            // ====== 阶段6: 签名 ======
            onProgress?.invoke(ProgressUpdate("加载签名证书...", 0.60f))
            val keystoreFile = File(context.filesDir, "security_guard.keystore")
            if (!keystoreFile.exists()) {
                context.assets.open("security_guard.keystore").use { input ->
                    FileOutputStream(keystoreFile).use { output -> input.copyTo(output) }
                }
            }

            val keystore = KeyStore.getInstance("PKCS12")
            keystore.load(FileInputStream(keystoreFile), "SecurityGuard2024!".toCharArray())
            val privateKey = keystore.getKey("security_guard_key", "SecurityGuard2024!".toCharArray()) as PrivateKey
            val cert = keystore.getCertificateChain("security_guard_key")[0] as X509Certificate

            onProgress?.invoke(ProgressUpdate("正在签名...", 0.70f))
            signApk(unsignedFile, outputFile, privateKey, cert)

            // 清理工作目录
            workDir.deleteRecursively()

            onProgress?.invoke(ProgressUpdate("完成!", 1.0f))
            details.appendLine("✓ 标准签名完成 (可直接安装)")

            ProcessResult(
                success = true,
                outputPath = outputFile.absolutePath,
                message = "加固完成！可直接安装",
                details = details.toString().trim()
            )
        } catch (e: Exception) {
            ProcessResult(false, null, "加固失败: ${e.message}", e.stackTraceToString())
        }
    }

    // ==================== 多层加密 ====================
    private fun multiLayerEncrypt(data: ByteArray, level: Int): ByteArray {
        var result = data
        val md = MessageDigest.getInstance("SHA-256")
        result = result + md.digest(result)
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
            result = ByteArray(result.size) { i -> (result[i].toInt() xor SEED[i % SEED.size].toInt()).toByte() }
        }
        return result
    }

    // ==================== 标准签名 ====================
    private fun signApk(unsignedApk: File, signedApk: File, privateKey: PrivateKey, cert: X509Certificate) {
        val digestMap = LinkedHashMap<String, ByteArray>()
        val fileData = LinkedHashMap<String, ByteArray>()

        java.util.zip.ZipFile(unsignedApk).use { zip ->
            zip.entries().asIterator().forEach { entry ->
                if (!entry.isDirectory && !entry.name.startsWith("META-INF/")) {
                    val data = zip.getInputStream(entry).readBytes()
                    fileData[entry.name] = data
                    digestMap[entry.name] = MessageDigest.getInstance("SHA-256").digest(data)
                }
            }
        }

        // MANIFEST.MF
        val manifest = JarManifest()
        manifest.mainAttributes.apply {
            putValue("Manifest-Version", "1.0")
            putValue("Created-By", "SecurityGuard (dpt-shell based)")
        }
        for ((name, digest) in digestMap) {
            val attr = Attributes()
            attr.putValue("SHA-256-Digest", Base64.encodeToString(digest, Base64.NO_WRAP))
            manifest.entries[name] = attr
        }
        val manifestBytes = ByteArrayOutputStream().also { manifest.write(it) }.toByteArray()

        // CERT.SF
        val sfContent = buildString {
            appendLine("Signature-Version: 1.0")
            appendLine("SHA-256-Digest-Manifest: ${Base64.encodeToString(MessageDigest.getInstance("SHA-256").digest(manifestBytes), Base64.NO_WRAP)}")
            appendLine("Created-By: SecurityGuard (dpt-shell based)")
            appendLine()
            for ((name, digest) in digestMap) {
                val md = MessageDigest.getInstance("SHA-256")
                val entryHeader = "Name: $name\r\n"
                val entryDigest = "SHA-256-Digest: ${Base64.encodeToString(digest, Base64.NO_WRAP)}\r\n\r\n"
                appendLine("Name: $name")
                appendLine("SHA-256-Digest: ${Base64.encodeToString(md.digest((entryHeader + entryDigest).toByteArray()), Base64.NO_WRAP)}")
                appendLine()
            }
        }
        val sfBytes = sfContent.toByteArray()

        // PKCS7 (BouncyCastle)
        val certList = ArrayList<X509Certificate>().also { it.add(cert) }
        val certStore = JcaCertStore(certList)
        val dp = JcaDigestCalculatorProviderBuilder().build()
        val sigGen = JcaSignerInfoGeneratorBuilder(dp).build(JcaContentSignerBuilder("SHA256withRSA").build(privateKey), cert)
        val gen = CMSSignedDataGenerator().also { it.addSignerInfoGenerator(sigGen); it.addCertificates(certStore) }
        val pkcs7 = gen.generate(CMSProcessableByteArray(sfBytes), true).encoded

        // 写入签名 APK
        ZipOutputStream(BufferedOutputStream(FileOutputStream(signedApk))).use { out ->
            for ((name, data) in fileData) {
                out.putNextEntry(ZipEntry(name))
                out.write(data)
                out.closeEntry()
            }
            for ((name, data) in arrayOf("MANIFEST.MF" to manifestBytes, "CERT.SF" to sfBytes, "CERT.RSA" to pkcs7)) {
                out.putNextEntry(ZipEntry("META-INF/$name"))
                out.write(data)
                out.closeEntry()
            }
        }
    }

    private fun loadShellDex(context: Context) = context.assets.open(SHELL_DEX_ASSET).readBytes()

    fun getApkInfo(apkPath: String): Map<String, String> {
        return try {
            val file = File(apkPath)
            val info = mutableMapOf<String, String>()
            info["文件名"] = file.name
            info["大小"] = "%.1f MB".format(file.length() / 1024.0 / 1024.0)
            ZipFile(file).use { zip ->
                var dexCount = 0; var dexSize = 0L
                zip.fileHeaders.forEach { h ->
                    if (h.fileName.endsWith(".dex")) { dexCount++; dexSize += h.uncompressedSize }
                }
                info["DEX 数量"] = "$dexCount 个"
                info["DEX 总大小"] = "%.1f KB".format(dexSize / 1024.0)
                info["条目总数"] = "${zip.fileHeaders.size}"
            }
            info
        } catch (e: Exception) {
            mapOf("错误" to (e.message ?: "未知"))
        }
    }
}