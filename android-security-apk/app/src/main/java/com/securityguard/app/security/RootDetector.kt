package com.securityguard.app.security

import java.io.File

/**
 * Root 检测模块
 * 检测设备是否已获得 Root 权限，防止提权攻击
 */
object RootDetector {

    data class RootResult(
        val isRooted: Boolean,
        val details: String,
        val detections: List<String>
    )

    // 常见的 Root 管理应用包名
    private val rootApps = arrayOf(
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot"
    )

    // 常见的 SU 二进制文件路径
    private val suPaths = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/vendor/bin/su"
    )

    // 常见的 Root 相关文件
    private val rootFiles = arrayOf(
        "/system/app/SuperSU.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/data/local/tmp/magisk",
        "/data/adb/magisk",
        "/cache/magisk.log",
        "/data/magisk.img",
        "/system/xbin/busybox",
        "/system/bin/busybox"
    )

    /**
     * 执行全面的 Root 检测
     */
    fun detect(): RootResult {
        val detections = mutableListOf<String>()
        var isRooted = false

        // 1. 检测 Root 管理应用
        val foundRootApps = checkRootApps()
        if (foundRootApps.isNotEmpty()) {
            detections.add("发现 Root 管理应用: ${foundRootApps.joinToString(", ")}")
            isRooted = true
        }

        // 2. 检测 SU 二进制文件
        val foundSuPaths = checkSuBinaries()
        if (foundSuPaths.isNotEmpty()) {
            detections.add("发现 SU 二进制文件: ${foundSuPaths.joinToString(", ")}")
            isRooted = true
        }

        // 3. 检测 Root 相关文件
        val foundRootFiles = checkRootFiles()
        if (foundRootFiles.isNotEmpty()) {
            detections.add("发现 Root 相关文件: ${foundRootFiles.size} 个")
            isRooted = true
        }

        // 4. 检测系统属性
        if (checkBuildTags()) {
            detections.add("检测到非官方系统构建 (test-keys)")
            isRooted = true
        }

        // 5. 检测 SELinux 状态
        if (checkSelinux()) {
            detections.add("SELinux 处于宽容模式")
            isRooted = true
        }

        return RootResult(
            isRooted = isRooted,
            details = if (isRooted) {
                "设备已 Root，存在 ${detections.size} 个风险特征"
            } else {
                "设备未 Root，运行环境安全"
            },
            detections = detections.ifEmpty { listOf("未发现 Root 特征") }
        )
    }

    private fun checkRootApps(): List<String> {
        return rootApps.filter { path ->
            File(path).exists()
        }
    }

    private fun checkSuBinaries(): List<String> {
        return suPaths.filter { path ->
            File(path).exists()
        }
    }

    private fun checkRootFiles(): List<String> {
        return rootFiles.filter { path ->
            File(path).exists()
        }
    }

    /**
     * 检查 Build.TAGS 是否包含 test-keys
     */
    private fun checkBuildTags(): Boolean {
        return try {
            val buildTags = android.os.Build.TAGS
            buildTags != null && buildTags.contains("test-keys")
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查 SELinux 状态
     */
    private fun checkSelinux(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getenforce"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result.equals("Permissive", ignoreCase = true)
        } catch (e: Exception) {
            false
        }
    }
}