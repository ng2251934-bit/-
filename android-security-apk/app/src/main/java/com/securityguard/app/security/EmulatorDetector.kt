package com.securityguard.app.security

import android.os.Build
import java.io.File

/**
 * 模拟器检测模块
 * 检测应用是否运行在模拟器环境中
 */
object EmulatorDetector {

    data class EmulatorResult(
        val isEmulator: Boolean,
        val details: String,
        val detections: List<String>
    )

    // 已知的模拟器特征
    private val emulatorCharacteristics = mapOf(
        "ro.product.manufacturer" to listOf("Genymotion", "unknown", "Google"),
        "ro.product.model" to listOf("sdk", "google_sdk", "sdk_google", "Android SDK built for x86"),
        "ro.hardware" to listOf("goldfish", "ranchu", "vbox86"),
        "ro.kernel.qemu" to listOf("1")
    )

    /**
     * 执行模拟器检测
     */
    fun detect(): EmulatorResult {
        val detections = mutableListOf<String>()
        var isEmulator = false

        // 1. 检查 Build 信息
        val buildChecks = checkBuildInfo()
        if (buildChecks.isNotEmpty()) {
            detections.addAll(buildChecks)
            isEmulator = true
        }

        // 2. 检查硬件特征
        if (checkHardware()) {
            detections.add("检测到模拟器硬件特征 (goldfish/ranchu/vbox86)")
            isEmulator = true
        }

        // 3. 检查系统属性
        val propChecks = checkSystemProperties()
        if (propChecks.isNotEmpty()) {
            detections.addAll(propChecks)
            isEmulator = true
        }

        // 4. 检查传感器
        if (checkSensors()) {
            detections.add("检测到模拟器传感器特征（缺少真实传感器）")
            isEmulator = true
        }

        // 5. 检查 CPU 架构
        if (checkCpuArch()) {
            detections.add("检测到 x86 CPU 架构（真机通常为 ARM）")
            isEmulator = true
        }

        return EmulatorResult(
            isEmulator = isEmulator,
            details = if (isEmulator) {
                "当前运行在模拟器环境中，发现 ${detections.size} 个模拟器特征"
            } else {
                "当前运行在真实设备上，环境安全"
            },
            detections = detections.ifEmpty { listOf("未发现模拟器特征") }
        )
    }

    /**
     * 检查 Build 信息
     */
    private fun checkBuildInfo(): List<String> {
        val results = mutableListOf<String>()

        if (Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
            Build.FINGERPRINT.contains("test-keys", ignoreCase = true)) {
            results.add("Build指纹包含 generic/test-keys")
        }

        if (Build.MODEL.contains("sdk", ignoreCase = true) ||
            Build.MODEL.contains("Emulator", ignoreCase = true) ||
            Build.MODEL.contains("Android SDK", ignoreCase = true)) {
            results.add("设备型号为模拟器特征: ${Build.MODEL}")
        }

        if (Build.MANUFACTURER.contains("Genymotion", ignoreCase = true) ||
            Build.MANUFACTURER.contains("unknown", ignoreCase = true)) {
            results.add("制造商为模拟器特征: ${Build.MANUFACTURER}")
        }

        if (Build.HARDWARE.contains("goldfish", ignoreCase = true) ||
            Build.HARDWARE.contains("ranchu", ignoreCase = true)) {
            results.add("硬件名称为模拟器特征: ${Build.HARDWARE}")
        }

        return results
    }

    /**
     * 检查硬件信息
     */
    private fun checkHardware(): Boolean {
        return Build.HARDWARE.contains("goldfish", ignoreCase = true) ||
                Build.HARDWARE.contains("ranchu", ignoreCase = true) ||
                Build.HARDWARE.contains("vbox86", ignoreCase = true)
    }

    /**
     * 检查系统属性
     */
    private fun checkSystemProperties(): List<String> {
        val results = mutableListOf<String>()
        try {
            val propsToCheck = listOf(
                "ro.kernel.qemu" to "1",
                "ro.kernel.android.qemud" to "1",
                "init.svc.qemud" to "running",
                "init.svc.qemu-props" to "running",
                "qemu.hw.mainkeys" to "0",
                "qemu.sf.lcd_density" to null
            )

            for ((prop, expectedValue) in propsToCheck) {
                val process = Runtime.getRuntime().exec(arrayOf("getprop", prop))
                val value = process.inputStream.bufferedReader().readText().trim()
                process.waitFor()
                if (value.isNotEmpty()) {
                    results.add("模拟器属性: $prop = $value")
                }
            }
        } catch (e: Exception) {
            // 忽略异常
        }
        return results
    }

    /**
     * 检查传感器数量
     */
    private fun checkSensors(): Boolean {
        return try {
            // 真实设备通常有多个传感器，模拟器传感器较少
            // 通过检查常见传感器文件来判断
            val sensorDevices = listOf(
                "/dev/socket/qemud",
                "/dev/qemu_pipe"
            )
            sensorDevices.any { File(it).exists() }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 检查 CPU 架构
     */
    private fun checkCpuArch(): Boolean {
        val arch = Build.CPU_ABI ?: Build.SUPPORTED_ABIS?.firstOrNull()
        return arch?.contains("x86", ignoreCase = true) == true
    }
}