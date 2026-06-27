package com.securityguard.app.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Hook 框架检测模块
 * 检测 Xposed、Frida 等常见的 Hook 框架
 */
object HookDetector {

    data class HookResult(
        val isHooked: Boolean,
        val details: String,
        val detections: List<String>
    )

    // Xposed 相关类名
    private val xposedClasses = arrayOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XposedHelpers",
        "de.robv.android.xposed.XC_MethodHook",
        "de.robv.android.xposed.callbacks.XCallback",
        "de.robv.android.xposed.XSharedPreferences"
    )

    // Frida 相关特征
    private val fridaLibs = arrayOf(
        "frida-agent",
        "frida-gadget",
        "frida-server",
        "libfrida-gadget.so",
        "re.frida.server"
    )

    // 可疑的进程名
    private val suspiciousProcesses = arrayOf(
        "frida",
        "frida-server",
        "xposed",
        "magiskd",
        "magisk"
    )

    /**
     * 执行 Hook 框架检测
     */
    fun detect(context: Context): HookResult {
        val detections = mutableListOf<String>()
        var isHooked = false

        // 1. 检测 Xposed 类
        val xposedFound = checkXposedClasses()
        if (xposedFound.isNotEmpty()) {
            detections.add("检测到 Xposed 框架: ${xposedFound.joinToString(", ")}")
            isHooked = true
        }

        // 2. 检测 Xposed 安装包
        if (checkXposedPackage(context)) {
            detections.add("检测到 Xposed Installer 安装包")
            isHooked = true
        }

        // 3. 检测 Frida 特征
        val fridaFound = checkFrida()
        if (fridaFound.isNotEmpty()) {
            detections.addAll(fridaFound)
            isHooked = true
        }

        // 4. 检测 /proc/self/maps 中的可疑库
        val suspiciousLibs = checkProcMaps()
        if (suspiciousLibs.isNotEmpty()) {
            detections.add("内存映射中发现可疑库: ${suspiciousLibs.joinToString(", ")}")
            isHooked = true
        }

        // 5. 检测可疑进程
        val suspiciousProcs = checkSuspiciousProcesses()
        if (suspiciousProcs.isNotEmpty()) {
            detections.add("发现可疑进程: ${suspiciousProcs.joinToString(", ")}")
            isHooked = true
        }

        return HookResult(
            isHooked = isHooked,
            details = if (isHooked) {
                "检测到 Hook 框架，应用可能正在被动态分析"
            } else {
                "未检测到 Hook 框架，运行环境安全"
            },
            detections = detections.ifEmpty { listOf("未发现 Hook 特征") }
        )
    }

    /**
     * 通过反射检测 Xposed 类
     */
    private fun checkXposedClasses(): List<String> {
        return xposedClasses.filter { className ->
            try {
                Class.forName(className, false, javaClass.classLoader)
                true
            } catch (e: ClassNotFoundException) {
                false
            } catch (e: Exception) {
                false
            }
        }
    }

    /**
     * 检测 Xposed 安装包
     */
    private fun checkXposedPackage(context: Context): Boolean {
        return try {
            val xposedPackageNames = arrayOf(
                "de.robv.android.xposed.installer",
                "com.saurik.substrate",
                "de.robv.android.xposed"
            )
            xposedPackageNames.any { pkg ->
                try {
                    context.packageManager.getPackageInfo(pkg, 0)
                    true
                } catch (e: PackageManager.NameNotFoundException) {
                    false
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检测 Frida 特征
     */
    private fun checkFrida(): List<String> {
        val results = mutableListOf<String>()

        // 检查 Frida 库文件
        val libPaths = listOf(
            "/data/local/tmp",
            "/system/lib",
            "/system/lib64",
            "/data/app"
        )

        for (path in libPaths) {
            val dir = File(path)
            if (dir.exists() && dir.isDirectory) {
                dir.listFiles()?.forEach { file ->
                    if (fridaLibs.any { file.name.contains(it, ignoreCase = true) }) {
                        results.add("发现 Frida 文件: ${file.absolutePath}")
                    }
                }
            }
        }

        // 检查 Frida 默认端口
        try {
            val process = Runtime.getRuntime().exec(arrayOf("cat", "/proc/net/tcp"))
            val output = process.inputStream.bufferedReader().readText()
            // Frida 默认端口 27042 的十六进制为 69A2
            if (output.contains("69A2", ignoreCase = true)) {
                results.add("检测到 Frida 默认端口 27042 开放")
            }
        } catch (e: Exception) {
            // 忽略
        }

        return results
    }

    /**
     * 检查 /proc/self/maps 中的可疑库
     */
    private fun checkProcMaps(): List<String> {
        val suspicious = mutableListOf<String>()
        try {
            val file = File("/proc/self/maps")
            if (!file.exists()) return suspicious

            BufferedReader(InputStreamReader(file.inputStream())).use { reader ->
                val suspiciousPatterns = listOf(
                    "frida", "xposed", "substrate", "libhook",
                    "libcydia", "libinject", "libsubstrate"
                )

                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    for (pattern in suspiciousPatterns) {
                        if (line!!.contains(pattern, ignoreCase = true)) {
                            suspicious.add(line!!.trim())
                            break
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return suspicious
    }

    /**
     * 检查可疑进程
     */
    private fun checkSuspiciousProcesses(): List<String> {
        val results = mutableListOf<String>()
        try {
            val process = Runtime.getRuntime().exec(arrayOf("ps"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            for (procName in suspiciousProcesses) {
                if (output.contains(procName, ignoreCase = true)) {
                    results.add(procName)
                }
            }
        } catch (e: Exception) {
            // 忽略
        }
        return results
    }
}