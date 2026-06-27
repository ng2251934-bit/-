package com.securityguard.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 数据加密管理模块
 * 使用 AES-256-GCM 进行关键数据加密保护
 */
object CryptoManager {

    private const val KEY_ALIAS = "SecurityGuardMasterKey"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128
    private const val GCM_IV_LENGTH = 12

    data class CryptoResult(
        val isAvailable: Boolean,
        val details: String,
        val algorithm: String = "AES-256-GCM",
        val keyStoreProvider: String = "Android KeyStore (硬件级)"
    )

    /**
     * 检查加密模块是否可用
     */
    fun checkAvailability(): CryptoResult {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            val hasKey = keyStore.containsAlias(KEY_ALIAS)

            CryptoResult(
                isAvailable = true,
                details = if (hasKey) {
                    "加密模块就绪，密钥已存储在硬件安全模块中"
                } else {
                    "加密模块可用，将在首次使用时生成密钥"
                }
            )
        } catch (e: Exception) {
            CryptoResult(
                isAvailable = false,
                details = "加密模块初始化失败: ${e.message}"
            )
        }
    }

    /**
     * 获取或创建 AES 密钥
     */
    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        // 如果密钥已存在，直接返回
        if (keyStore.containsAlias(KEY_ALIAS)) {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry
            return entry.secretKey
        }

        // 生成新密钥
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(keyGenSpec)
        return keyGenerator.generateKey()
    }

    /**
     * 加密数据
     * @return EncryptedData 包含加密后的数据和 IV
     */
    fun encrypt(context: Context, plainText: String): EncryptedData? {
        return try {
            val secretKey = getOrCreateKey()
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val iv = cipher.iv
            val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

            EncryptedData(
                encryptedData = encryptedBytes,
                iv = iv
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 解密数据
     */
    fun decrypt(context: Context, encryptedData: EncryptedData): String? {
        return try {
            val secretKey = getOrCreateKey()
            val cipher = Cipher.getInstance(AES_TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

            val decryptedBytes = cipher.doFinal(encryptedData.encryptedData)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 加密测试
     */
    fun performEncryptionTest(): CryptoResult {
        return try {
            val testData = "SecurityGuard_EncryptionTest_${System.currentTimeMillis()}"
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            val encrypted = encrypt(android.app.Application().also { }, testData)

            if (encrypted != null) {
                val decrypted = decrypt(android.app.Application().also { }, encrypted)
                if (decrypted == testData) {
                    return CryptoResult(
                        isAvailable = true,
                        details = "加密测试通过，AES-256-GCM 加解密功能正常"
                    )
                }
            }

            CryptoResult(
                isAvailable = false,
                details = "加密测试失败：解密结果与原文不一致"
            )
        } catch (e: Exception) {
            CryptoResult(
                isAvailable = false,
                details = "加密测试异常: ${e.message}"
            )
        }
    }

    /**
     * 加密数据类
     */
    data class EncryptedData(
        val encryptedData: ByteArray,
        val iv: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EncryptedData
            return encryptedData.contentEquals(other.encryptedData) &&
                    iv.contentEquals(other.iv)
        }

        override fun hashCode(): Int {
            var result = encryptedData.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            return result
        }
    }
}