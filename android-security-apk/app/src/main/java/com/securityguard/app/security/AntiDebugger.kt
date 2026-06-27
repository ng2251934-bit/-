package com.securityguard.app.security

import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * 反调试检测模块
 * 检测应用是否被调试器附加，防止动态分析
 */
object AntiDebugger {

    data class DebugResult(
        val isDebugging: Boolean,
        val details: String,
        val detections: List<String>
    )

    /**
     * 执行全面的反调试检测
     */
    fun detect(): DebugResult {
        val detections = mutableListOf<String>()
        var isDebugging = false

        // 1. 检测 Android 调试标志
        if (Debug.isDebuggerConnected()) {
            detections.add("检测到调试器已连接 (Debug.isDebuggerConnected)")
            isDebugging = true
        }

        // 2. 检测 TracerPid（/proc/self/status）
        if (checkTracerPid()) {
            detections.add("检测到进程被追踪 (TracerPid != 0)")
            isDebugging = true
        }

        // 3. 检测调试相关系统属性
        if (checkDebuggableProp()) {
            detections.add("检测到应用处于可调试状态 (ro.debuggable)")
            isDebugging = true
        }

        // 4. 检测 JDWP 调试端口
        if (checkJdwpPort()) {
            detections.add("检测到 JDWP 调试端口开放")
            isDebugging = true
        }

        return DebugResult(
            isDebugging = isDebugging,
            details = if (isDebugging) {
                "发现 ${detections.size} 个调试特征，应用可能正在被分析"
            } else {
                "未检测到调试行为，应用运行环境安全"
            },
            detections = detections.ifEmpty { listOf("未发现调试特征") }
        )
    }

    /**
     * 检查 /proc/self/status 中的 TracerPid
     */
    private fun checkTracerPid(): Boolean {
        return try {
            val file = File("/proc/self/status")
            if (!file.exists()) return false

            BufferedReader(FileReader(file)).use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    if (line!!.startsWith("TracerPid:")) {
                        val pid = line!!.substringAfter("TracerPid:").trim().toIntOrNull() ?: 0
                        return pid != 0
                    }
                }
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查系统是否可调试
     */
    private fun checkDebuggableProp(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", "ro.debuggable"))
            val result = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            result == "1"
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查 JDWP 端口
     */
    private fun checkJdwpPort(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("cat", "/proc/net/tcp"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()
            // JDWP 默认端口 8700 的十六进制为 21FC
            output.contains("00000000:21FC", ignoreCase = true)
        } catch (e: Exception) {
            false
        }
    }
}