package com.securityguard.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
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
 * 第一层：XOR 动态密钥混淆
 * 第二层：自定义 Base64 解码
 * 第三层：AES-256-CBC 解密
 * 第四层：完整性校验
 */
public class ProxyApplication extends Application {

    private static final String ENC_DEX_ASSET = "assets/classes_encrypted.dex";
    // 密钥种子，会与设备信息混合生成最终密钥
    private static final byte[] SEED = {
        0x53, 0x47, 0x50, 0x72, 0x6F, 0x74, 0x65, 0x63,
        0x74, 0x32, 0x30, 0x32, 0x34, 0x21, 0x40, 0x23
    };
    // 自定义 Base64 映射表
    private static final char[] CUSTOM_BASE64 = 
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba0987654321+/=".toCharArray();

    private String realAppName;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            // 多层解密加载真实 DEX
            byte[] encrypted = readEncryptedDex(base);
            
            // 第一层：XOR 解密
            byte[] layer1 = xorDecrypt(encrypted, generateXorKey(base));
            
            // 第二层：自定义 Base64 解码
            byte[] layer2 = customBase64Decode(layer1);
            
            // 第三层：AES-256-CBC 解密
            byte[] realDex = aesDecrypt(layer2, generateAesKey(base));
            
            // 第四层：Md5 完整性校验
            if (!verifyIntegrity(realDex, base)) {
                throw new SecurityException("Integrity check failed");
            }
            
            // 加载真实 DEX
            loadRealDex(base, realDex);
        } catch (Exception e) {
            // 静默失败，防止被分析
            System.exit(0);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            if (realAppName != null && !realAppName.isEmpty()) {
                Application realApp = (Application) Class.forName(realAppName)
                    .newInstance();
                Method onCreate = Application.class.getDeclaredMethod("onCreate");
                onCreate.setAccessible(true);
                onCreate.invoke(realApp);
            }
        } catch (Exception e) {
            // 静默
        }
    }

    // ========== 第一层：XOR 动态密钥 ==========
    private byte[] generateXorKey(Context ctx) {
        try {
            // 混合设备指纹生成 XOR 密钥
            String fp = Build.MODEL + Build.MANUFACTURER + 
                ctx.getPackageName().hashCode();
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(
                fp.getBytes("UTF-8")
            );
            byte[] key = new byte[SEED.length];
            for (int i = 0; i < SEED.length; i++) {
                key[i] = (byte) (SEED[i] ^ hash[i % hash.length]);
            }
            return key;
        } catch (Exception e) {
            return SEED;
        }
    }

    private byte[] xorDecrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    // ========== 第二层：自定义 Base64 ==========
    private byte[] customBase64Decode(byte[] encoded) {
        // 先用标准 Base64 解码，再用自定义映射还原
        String encodedStr = new String(encoded);
        // 还原自定义映射
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < encodedStr.length(); i++) {
            char c = encodedStr.charAt(i);
            int idx = indexOf(CUSTOM_BASE64, c);
            if (idx >= 0) {
                sb.append("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(idx));
            } else {
                sb.append(c);
            }
        }
        return android.util.Base64.decode(sb.toString(), android.util.Base64.DEFAULT);
    }

    private int indexOf(char[] arr, char c) {
        for (int i = 0; i < arr.length; i++) {
            if (arr[i] == c) return i;
        }
        return -1;
    }

    // ========== 第三层：AES-256-CBC ==========
    private byte[] generateAesKey(Context ctx) {
        try {
            // 动态生成 AES 密钥：包名 + 签名哈希 + 固定种子
            String pkg = ctx.getPackageName();
            PackageManager pm = ctx.getPackageManager();
            android.content.pm.PackageInfo pi = pm.getPackageInfo(
                pkg, PackageManager.GET_SIGNATURES
            );
            String sigHash = "";
            if (pi.signatures != null && pi.signatures.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(pi.signatures[0].toByteArray());
                sigHash = bytesToHex(hash);
            }
            String keyMaterial = pkg + sigHash + "SecurityGuard_SecureKey_2024";
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(keyMaterial.getBytes("UTF-8"));
        } catch (Exception e) {
            return SEED;
        }
    }

    private byte[] aesDecrypt(byte[] data, byte[] key) throws Exception {
        // IV 是数据的前 16 字节
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

    // ========== 第四层：完整性校验 ==========
    private boolean verifyIntegrity(byte[] dex, Context ctx) {
        try {
            // 读取内置校验值（DEX 最后 32 字节）
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
        // 绕过 assets 路径限制
        String path = ENC_DEX_ASSET;
        if (path.startsWith("assets/")) {
            path = path.substring(7);
        }
        InputStream is = ctx.getAssets().open(path);
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

        DexClassLoader loader = new DexClassLoader(
            dexFile.getAbsolutePath(),
            dexDir.getAbsolutePath(),
            null,
            ctx.getClassLoader()
        );

        // 读取真实 Application 类名
        ApplicationInfo ai = ctx.getPackageManager()
            .getApplicationInfo(ctx.getPackageName(), PackageManager.GET_META_DATA);
        realAppName = ai.metaData != null ? 
            ai.metaData.getString("REAL_APP") : null;
    }

    // ========== 工具方法 ==========
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}