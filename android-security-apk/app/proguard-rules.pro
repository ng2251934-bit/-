# ===========================================
# SecurityGuard ProGuard 混淆规则
# 保护应用代码不被逆向分析
# ===========================================

# ---- 基础混淆设置 ----
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
-repackageclasses 'com.securityguard.internal'

# ---- 保留安全模块入口（不被混淆） ----
-keep class com.securityguard.app.SecurityApplication { *; }
-keep class com.securityguard.app.MainActivity { *; }

# ---- 保留 Compose 相关 ----
-keep class androidx.compose.** { *; }
-keep class kotlinx.coroutines.** { *; }

# ---- 保留加密相关类 ----
-keepclassmembers class * {
    @javax.crypto.spec.* <fields>;
}
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }

# ---- 保留 Android Keystore ----
-keep class android.security.keystore.** { *; }

# ---- 保留签名相关 ----
-keep class android.content.pm.Signature { *; }
-keep class android.content.pm.PackageInfo { *; }

# ---- 移除日志输出 ----
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
}

# ---- 字符串加密 ----
# 配合编译时字符串混淆工具使用

# ---- 资源混淆 ----
# 启用 R8 资源压缩

# ---- 防止反射 ----
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ---- Native 方法保护 ----
-keepclasseswithmembernames class * {
    native <methods>;
}

# ---- 保留枚举 ----
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ---- 保留 Serializable ----
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}