package com.securityguard.app.security

import android.content.Context

/**
 * 安全扫描器 - 汇总所有安全检测模块的结果
 */
class SecurityScanner(private val context: Context) {

    data class SecurityReport(
        val signature: SignatureVerifier.SignatureResult,
        val antiDebug: AntiDebugger.DebugResult,
        val rootDetect: RootDetector.RootResult,
        val emulatorDetect: EmulatorDetector.EmulatorResult,
        val crypto: CryptoManager.CryptoResult,
        val hookDetect: HookDetector.HookResult,
        val overallScore: Int,
        val overallStatus: SecurityStatus,
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class SecurityStatus {
        SAFE,       // 安全 - 总分 >= 90
        WARNING,    // 警告 - 总分 >= 60
        DANGER      // 危险 - 总分 < 60
    }

    data class SecurityItem(
        val name: String,
        val description: String,
        val icon: String,
        val isPassed: Boolean,
        val details: String,
        val weight: Int // 权重
    )

    /**
     * 执行完整的安全扫描
     */
    fun performFullScan(): SecurityReport {
        val signatureResult = SignatureVerifier.verify(context)
        val antiDebugResult = AntiDebugger.detect()
        val rootResult = RootDetector.detect()
        val emulatorResult = EmulatorDetector.detect()
        val cryptoResult = CryptoManager.checkAvailability()
        val hookResult = HookDetector.detect(context)

        // 计算总分 (满分 100)
        var score = 100
        if (!signatureResult.isValid) score -= 15
        if (antiDebugResult.isDebugging) score -= 15
        if (rootResult.isRooted) score -= 20
        if (emulatorResult.isEmulator) score -= 15
        if (!cryptoResult.isAvailable) score -= 15
        if (hookResult.isHooked) score -= 20

        score = score.coerceIn(0, 100)

        val status = when {
            score >= 90 -> SecurityStatus.SAFE
            score >= 60 -> SecurityStatus.WARNING
            else -> SecurityStatus.DANGER
        }

        return SecurityReport(
            signature = signatureResult,
            antiDebug = antiDebugResult,
            rootDetect = rootResult,
            emulatorDetect = emulatorResult,
            crypto = cryptoResult,
            hookDetect = hookResult,
            overallScore = score,
            overallStatus = status
        )
    }

    /**
     * 获取安全检测项列表（用于 UI 展示）
     */
    fun getSecurityItems(report: SecurityReport): List<SecurityItem> {
        return listOf(
            SecurityItem(
                name = "签名校验",
                description = "验证 APK 签名完整性，防止二次打包",
                icon = "fingerprint",
                isPassed = report.signature.isValid,
                details = report.signature.details,
                weight = 15
            ),
            SecurityItem(
                name = "反调试检测",
                description = "检测是否被调试器附加，防止动态分析",
                icon = "bug_report",
                isPassed = !report.antiDebug.isDebugging,
                details = report.antiDebug.details,
                weight = 15
            ),
            SecurityItem(
                name = "Root 检测",
                description = "检测设备是否已 Root，防止提权攻击",
                icon = "security",
                isPassed = !report.rootDetect.isRooted,
                details = report.rootDetect.details,
                weight = 20
            ),
            SecurityItem(
                name = "模拟器检测",
                description = "检测是否运行在模拟器环境",
                icon = "phone_android",
                isPassed = !report.emulatorDetect.isEmulator,
                details = report.emulatorDetect.details,
                weight = 15
            ),
            SecurityItem(
                name = "数据加密",
                description = "AES-256-GCM 硬件级加密保护",
                icon = "lock",
                isPassed = report.crypto.isAvailable,
                details = report.crypto.details,
                weight = 15
            ),
            SecurityItem(
                name = "Hook 检测",
                description = "检测 Xposed/Frida 等 Hook 框架",
                icon = "flash_on",
                isPassed = !report.hookDetect.isHooked,
                details = report.hookDetect.details,
                weight = 20
            )
        )
    }
}