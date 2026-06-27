package com.securityguard.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import dalvik.system.DexClassLoader;

/**
 * Shell Application - 多层加密壳
 * 解密顺序：XOR → 自定义Base64 → AES-256-CBC → SHA256校验
 */
public class ProxyApplication extends Application {

    private static final String ENC_DEX_PATH = "classes_encrypted.dex";
    private static final byte[] SEED = {
        0x53, 0x47, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
        0x74, 0x32, 0x30, 0x32, 0x34, 0x21, 0x40, 0x23
    };
    private static final char[] CUSTOM_BASE64 = 
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/=".toCharArray();
    private static final String AES_KEY_MATERIAL = "SecurityGuard_SecureKey_2024";
    private static final String STANDARD_BASE64_CHARS = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    private String realAppName;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            // 读取加密 DEX
            byte[] encrypted = readEncryptedDex(base);
            
            // 第一层：XOR 解密（固定密钥，与 Processor 一致）
            byte[] layer1 = xorDecrypt(encrypted, SEED);
            
            // 第二层：自定义 Base64 解码
            byte[] layer2 = customBase64Decode(layer1);
            
            // 第三层：AES-256-CBC 解密
            byte[] realDex = aesDecrypt(layer2, generateAesKey());
            
            // 第四层：SHA-256 完整性校验
            if (!verifyIntegrity(realDex)) {
                throw new SecurityException("Integrity check failed");
            }
            
            // 加载真实 DEX
            loadRealDex(base, realDex);
        } catch (Exception e) {
            System.exit(0);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            if (realAppName != null && !realAppName.isEmpty()) {
                Application realApp = (Application) Class.forName(realAppName).newInstance();
                Method onCreate = Application.class.getDeclaredMethod("onCreate");
                onCreate.setAccessible(true);
                onCreate.invoke(realApp);
            }
        } catch (Exception ignored) {
        }
    }

    // ========== 第一层：XOR 解密 ==========
    private byte[] xorDecrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    // ========== 第二层：自定义 Base64 解码 ==========
    private byte[] customBase64Decode(byte[] encoded) {
        String encodedStr = new String(encoded);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encodedStr.length(); i++) {
            char c = encodedStr.charAt(i);
            int idx = -1;
            for (int j = 0; j < CUSTOM_BASE64.length; j++) {
                if (CUSTOM_BASE64[j] == c) { idx = j; break; }
            }
            if (idx >= 0) {
                sb.append(STANDARD_BASE64_CHARS.charAt(idx));
            } else {
                sb.append(c);
            }
        }
        return android.util.Base64.decode(sb.toString(), android.util.Base64.DEFAULT);
    }

    // ========== 第三层：AES-256-CBC 解密 ==========
    private byte[] generateAesKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(AES_KEY_MATERIAL.getBytes("UTF-8"));
        } catch (Exception e) {
            return SEED;
        }
    }

    private byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(data, 0, iv, 0, 16);
        byte[] encrypted = new byte[data.length - 16];
        System.arraycopy(data, 16, encrypted, 0, encrypted.length);

        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(encrypted);
    }

    // ========== 第四层：SHA-256 完整性校验 ==========
    private boolean verifyIntegrity(byte[] dex) {
        try {
            int checkLen = 32;
            byte[] dexData = new byte[dex.length - checkLen];
            byte[] storedHash = new byte[checkLen];
            System.arraycopy(dex, 0, dexData, 0, dexData.length);
            System.arraycopy(dex, dexData.length, storedHash, 0, checkLen);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] computedHash = md.digest(dexData);
            return MessageDigest.isEqual(storedHash, computedHash);
        } catch (Exception e) {
            return false;
        }
    }

    // ========== DEX 加载 ==========
    private byte[] readEncryptedDex(Context ctx) throws Exception {
        InputStream is = ctx.getAssets().open(ENC_DEX_PATH);
        byte[] data = new byte[is.available()];
        int offset = 0;
        while (offset < data.length) {
            int read = is.read(data, offset, data.length - offset);
            if (read < 0) break;
            offset += read;
        }
        is.close();
        return data;
    }

    private void loadRealDex(Context ctx, byte[] dexData) throws Exception {
        File dexDir = ctx.getDir("sg_dex", Context.MODE_PRIVATE);
        File dexFile = new File(dexDir, "real.dex");
        FileOutputStream fos = new FileOutputStream(dexFile);
        fos.write(dexData);
        fos.close();

        // 读取真实 Application 类名（从 meta-data 获取）
        try {
            ApplicationInfo ai = ctx.getPackageManager()
                .getApplicationInfo(ctx.getPackageName(), PackageManager.GET_META_DATA);
            if (ai.metaData != null) {
                realAppName = ai.metaData.getString("SG_REAL_APP");
            }
        } catch (Exception ignored) {
        }

        // 加载 DEX 到当前 ClassLoader
        DexClassLoader loader = new DexClassLoader(
            dexFile.getAbsolutePath(),
            dexDir.getAbsolutePath(),
            null,
            ctx.getClassLoader()
        );

        // 用反射替换 ClassLoader 的 pathList，追加我们的 DEX
        try {
            ClassLoader parentLoader = ctx.getClassLoader();
            java.lang.reflect.Field pathListField = 
                findField(parentLoader.getClass(), "pathList");
            if (pathListField != null) {
                pathListField.setAccessible(true);
                Object pathList = pathListField.get(parentLoader);
                
                java.lang.reflect.Field dexElementsField = 
                    findField(pathList.getClass(), "dexElements");
                if (dexElementsField != null) {
                    dexElementsField.setAccessible(true);
                    Object[] existingElements = 
                        (Object[]) dexElementsField.get(pathList);
                    
                    // 获取 loader 的 dexElements
                    Object loaderPathList = pathListField.get(loader);
                    Object[] newElements = 
                        (Object[]) dexElementsField.get(loaderPathList);
                    
                    // 合并
                    Object[] combined = new Object[existingElements.length + newElements.length];
                    System.arraycopy(newElements, 0, combined, 0, newElements.length);
                    System.arraycopy(existingElements, 0, combined, newElements.length, existingElements.length);
                    dexElementsField.set(pathList, combined);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private java.lang.reflect.Field findField(Class<?> clazz, String name) {
        Class<?> c = clazz;
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        return null;
    }
}