package com.securityguard.app

import android.app.Application
import com.securityguard.app.security.CryptoManager

/**
 * 应用入口类
 * 在应用启动时初始化安全模块
 */
class SecurityApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        initializeSecurity()
    }

    /**
     * 初始化安全模块
     */
    private fun initializeSecurity() {
        // 预初始化加密模块，触发密钥生成
        try {
            CryptoManager.checkAvailability()
        } catch (e: Exception) {
            // 加密模块初始化失败，不影响应用正常运行
        }
    }
}