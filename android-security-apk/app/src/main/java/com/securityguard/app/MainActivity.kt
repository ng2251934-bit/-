package com.securityguard.app

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.securityguard.app.protector.ApkProcessor
import com.securityguard.app.protector.ApkProcessor.ProgressUpdate
import com.securityguard.app.ui.theme.*
import kotlinx.coroutines.*
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SecurityGuardTheme {
                ProtectorScreen()
            }
        }
    }
}

@Composable
fun ProtectorScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var selectedApk by remember { mutableStateOf<Uri?>(null) }
    var apkInfo by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var encryptionLevel by remember { mutableIntStateOf(3) }
    var isProcessing by remember { mutableStateOf(false) }
    var progressText by remember { mutableStateOf("") }
    var progressValue by remember { mutableFloatStateOf(0f) }
    var result by remember { mutableStateOf<ApkProcessor.ProcessResult?>(null) }
    var showPermissionDialog by remember { mutableStateOf(false) }
    var job by remember { mutableStateOf<Job?>(null) }

    val apkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            selectedApk = uri
            result = null
            val path = uri.path ?: ""
            apkInfo = ApkProcessor.getApkInfo(path)
        }
    }

    LaunchedEffect(Unit) {
        if (!Environment.isExternalStorageManager()) showPermissionDialog = true
    }

    if (showPermissionDialog) {
        AlertDialog(
            onDismissRequest = { showPermissionDialog = false },
            containerColor = CardDark, titleContentColor = TextWhite, textContentColor = TextGray,
            title = { Text("存储权限") },
            text = { Text("需要「所有文件访问权限」来读取和保存 APK") },
            confirmButton = {
                TextButton(onClick = {
                    showPermissionDialog = false
                    context.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                        data = Uri.parse("package:${context.packageName}")
                    })
                }) { Text("授权", color = CyberBlue) }
            },
            dismissButton = {
                TextButton(onClick = { showPermissionDialog = false }) { Text("稍后", color = TextDim) }
            }
        )
    }

    fun startProtect() {
        if (isProcessing) return
        isProcessing = true
        result = null
        progressValue = 0f
        progressText = "准备中..."

        job = scope.launch(Dispatchers.IO) {
            try {
                val outputDir = context.getExternalFilesDir("protected")?.absolutePath ?: context.filesDir.absolutePath

                // 复制输入文件到缓存
                ensureActive()
                withContext(Dispatchers.Main) { progressText = "复制文件到缓存..."; progressValue = 0.02f }

                val tmpFile = File(context.cacheDir, "input_${System.currentTimeMillis()}.apk")
                selectedApk?.let { uri ->
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        tmpFile.outputStream().use { output -> input.copyTo(output) }
                    }
                }
                ensureActive()

                val options = ApkProcessor.ProtectOptions(enableDexEncryption = true, encryptionLevel = encryptionLevel)

                val procResult = ApkProcessor.protectApk(context, tmpFile.absolutePath, outputDir, options) { update ->
                    if (!isActive) return@protectApk
                    android.os.Handler(android.os.Looper.getMainLooper()).post {
                        progressText = update.step
                        progressValue = update.progress
                    }
                }

                // 清理缓存
                tmpFile.delete()

                ensureActive()
                withContext(Dispatchers.Main) {
                    result = procResult
                    isProcessing = false
                    progressValue = if (procResult.success) 1f else 0f
                }
            } catch (e: CancellationException) {
                withContext(Dispatchers.Main) {
                    isProcessing = false
                    progressValue = 0f
                    progressText = ""
                    Toast.makeText(context, "已取消", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    isProcessing = false
                    result = ApkProcessor.ProcessResult(false, null, "错误: ${e.message}", e.stackTraceToString())
                }
            }
        }
    }

    fun cancelProtect() {
        job?.cancel()
        isProcessing = false
    }

    Box(
        modifier = Modifier.fillMaxSize().background(Brush.verticalGradient(GradientDark))
    ) {
        ParticleBackground()

        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(48.dp))
            HeaderSection()
            Spacer(Modifier.height(24.dp))

            FileSelectorCard(
                selectedApk = selectedApk,
                apkInfo = apkInfo,
                onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive")) }
            )

            if (selectedApk != null) {
                Spacer(Modifier.height(20.dp))
                EncryptionConfigCard(level = encryptionLevel, onLevelChange = { encryptionLevel = it })

                Spacer(Modifier.height(20.dp))
                ProtectButton(
                    isProcessing = isProcessing,
                    progressText = progressText,
                    progressValue = progressValue,
                    onClick = { startProtect() },
                    onCancel = { cancelProtect() }
                )
            }

            if (result != null) {
                Spacer(Modifier.height(20.dp))
                ResultCard(result = result!!)
            }

            Spacer(Modifier.height(40.dp))
            FooterSection()
            Spacer(Modifier.height(32.dp))
        }
    }
}

// ==================== 粒子背景 ====================
@Composable
fun ParticleBackground() {
    val infiniteTransition = rememberInfiniteTransition(label = "particles")
    val particles = remember { List(12) { Triple((Math.random() * 1000).toFloat(), (Math.random() * 2000).toFloat(), (Math.random() * 3 + 1).toFloat()) } }
    val offsets = particles.map { (x, _, speed) ->
        infiniteTransition.animateFloat((Math.random() * 2000).toFloat(), -200f,
            infiniteRepeatable(tween((20000 / speed).toInt(), easing = LinearEasing), RepeatMode.Restart), label = "p_$x")
    }
    Canvas(modifier = Modifier.fillMaxSize()) {
        particles.forEachIndexed { i, (x, _, size) ->
            drawCircle(Color.White.copy(alpha = 0.03f * size), size * 2f, Offset(x, offsets[i].value))
        }
    }
}

// ==================== 头部 ====================
@Composable
fun HeaderSection() {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(1f, 1.15f, infiniteRepeatable(tween(2000, easing = EaseInOutCubic), RepeatMode.Reverse), label = "ps")
    val rotateAngle by infiniteTransition.animateFloat(0f, 360f, infiniteRepeatable(tween(20000, easing = LinearEasing), RepeatMode.Restart), label = "rot")

    Box(modifier = Modifier.size(120.dp), contentAlignment = Alignment.Center) {
        Canvas(modifier = Modifier.size(100.dp * pulseScale)) {
            drawArc(Brush.sweepGradient(listOf(CyberBlue.copy(alpha = 0f), CyberBlue.copy(alpha = 0.4f), CyberBlue.copy(alpha = 0f))),
                rotateAngle, 120f, false, style = Stroke(width = 2.dp.toPx()))
        }
        Box(modifier = Modifier.size(72.dp).clip(CircleShape).background(Brush.linearGradient(listOf(CardDark, CardDarkAlt)))
            .border(1.5.dp, CyberBlue.copy(alpha = 0.3f), CircleShape), contentAlignment = Alignment.Center) {
            Icon(Icons.Filled.Security, null, tint = CyberBlue, modifier = Modifier.size(36.dp))
        }
    }
    Spacer(Modifier.height(16.dp))
    Text("APK 加固卫士", fontSize = 26.sp, fontWeight = FontWeight.Bold, color = TextWhite, letterSpacing = 2.sp)
    Spacer(Modifier.height(6.dp))
    Text("MULTI-LAYER ENCRYPTION · 多层加密加固", fontSize = 11.sp, color = TextDim, letterSpacing = 4.sp)
}

// ==================== 文件选择卡片 ====================
@Composable
fun FileSelectorCard(selectedApk: Uri?, apkInfo: Map<String, String>, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        border = BorderStroke(1.dp, if (selectedApk != null) ElectricGreen.copy(alpha = 0.4f) else CyberBlue.copy(alpha = 0.2f))
    ) {
        Box(modifier = Modifier.fillMaxWidth().background(Brush.linearGradient(
            if (selectedApk != null) listOf(CardDark.copy(alpha = 0.9f), CardDarkAlt.copy(alpha = 0.8f))
            else listOf(CardDark.copy(alpha = 0.7f), CardDark.copy(alpha = 0.5f))
        )).padding(28.dp), contentAlignment = Alignment.Center) {
            if (selectedApk == null) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(modifier = Modifier.size(80.dp).clip(RoundedCornerShape(16.dp)).background(CyberBlue.copy(alpha = 0.05f))
                        .border(1.dp, CyberBlue.copy(alpha = 0.2f), RoundedCornerShape(16.dp)), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.CloudUpload, null, tint = CyberBlue.copy(alpha = 0.6f), modifier = Modifier.size(40.dp))
                    }
                    Spacer(Modifier.height(16.dp))
                    Text("选择 APK 文件", fontSize = 15.sp, fontWeight = FontWeight.Medium, color = TextWhite)
                    Spacer(Modifier.height(4.dp))
                    Text("点击此处选择需要加固的 APK", fontSize = 12.sp, color = TextDim)
                }
            } else {
                Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.size(52.dp).clip(RoundedCornerShape(14.dp)).background(ElectricGreen.copy(alpha = 0.1f)), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.Android, null, tint = ElectricGreen, modifier = Modifier.size(30.dp))
                    }
                    Spacer(Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(apkInfo["文件名"] ?: "已选择", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextWhite, maxLines = 1)
                        Spacer(Modifier.height(4.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            apkInfo["大小"]?.let { LabelBadge(it, CyberBlue) }
                            apkInfo["DEX 数量"]?.let { LabelBadge(it, CyberPurple) }
                        }
                    }
                    Icon(Icons.Filled.CheckCircle, null, tint = ElectricGreen, modifier = Modifier.size(24.dp))
                }
            }
        }
    }
}

@Composable
fun LabelBadge(text: String, color: Color) {
    Box(modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(color.copy(alpha = 0.1f)).padding(horizontal = 8.dp, vertical = 2.dp)) {
        Text(text, fontSize = 11.sp, color = color.copy(alpha = 0.8f), fontWeight = FontWeight.Medium)
    }
}

// ==================== 加密配置卡片 ====================
@Composable
fun EncryptionConfigCard(level: Int, onLevelChange: (Int) -> Unit) {
    Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        border = BorderStroke(1.dp, CyberPurple.copy(alpha = 0.2f))) {
        Box(modifier = Modifier.fillMaxWidth().background(Brush.linearGradient(GradientCard)).padding(24.dp)) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Tune, null, tint = CyberPurple, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("加密强度", fontSize = 15.sp, fontWeight = FontWeight.Bold, color = TextWhite)
                    Spacer(Modifier.weight(1f))
                    Text("LEVEL $level", fontSize = 11.sp, color = TextDim, letterSpacing = 2.sp)
                }
                Spacer(Modifier.height(16.dp))

                data class LvlOpt(val lvl: Int, val title: String, val tech: String, val color: Color, val badge: String)
                listOf(
                    LvlOpt(1, "基础防护", "AES-256-CBC", CyberBlue, "仅文件校验"),
                    LvlOpt(2, "标准防护", "AES + Base64混淆", CyberPurple, "推荐商用"),
                    LvlOpt(3, "深度防护", "XOR + Base64 + AES + SHA256", CyberPink, "军事级加密")
                ).forEach { opt ->
                    val sel = opt.lvl == level
                    Box(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(14.dp))
                        .background(if (sel) opt.color.copy(alpha = 0.08f) else Color.Transparent)
                        .border(1.dp, if (sel) opt.color.copy(alpha = 0.3f) else Color.Transparent, RoundedCornerShape(14.dp))
                        .clickable { onLevelChange(opt.lvl) }.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(modifier = Modifier.size(40.dp).clip(RoundedCornerShape(10.dp)).background(opt.color.copy(alpha = 0.1f)), contentAlignment = Alignment.Center) {
                                Icon(when(opt.lvl){1->Icons.Filled.Shield; 2->Icons.Filled.EnhancedEncryption; else->Icons.Filled.Lock}, null, tint = opt.color, modifier = Modifier.size(22.dp))
                            }
                            Spacer(Modifier.width(14.dp))
                            Column(Modifier.weight(1f)) { Text(opt.title, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = TextWhite); Text(opt.tech, fontSize = 11.sp, color = TextGray) }
                            Column(horizontalAlignment = Alignment.End) {
                                Text(opt.badge, fontSize = 10.sp, color = opt.color.copy(alpha = 0.7f))
                                Spacer(Modifier.height(2.dp))
                                if (sel) Box(Modifier.size(8.dp).clip(CircleShape).background(opt.color))
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==================== 加固按钮 ====================
@Composable
fun ProtectButton(isProcessing: Boolean, progressText: String, progressValue: Float, onClick: () -> Unit, onCancel: () -> Unit) {
    val infiniteTransition = rememberInfiniteTransition(label = "btnGlow")
    val glowAlpha by infiniteTransition.animateFloat(0.3f, 0.7f, infiniteRepeatable(tween(1500), RepeatMode.Reverse), label = "glow")

    Column(modifier = Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        // 进度条
        if (isProcessing) {
            Spacer(Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = progressValue,
                modifier = Modifier.fillMaxWidth().height(3.dp).clip(RoundedCornerShape(2.dp)),
                color = CyberBlue, trackColor = CyberBlue.copy(alpha = 0.1f)
            )
            Spacer(Modifier.height(6.dp))
            Text(progressText, fontSize = 11.sp, color = TextGray)
            Spacer(Modifier.height(8.dp))
        }

        Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            if (!isProcessing) {
                Box(modifier = Modifier.fillMaxWidth(0.9f).height(56.dp).offset(y = 4.dp).clip(RoundedCornerShape(18.dp))
                    .background(Brush.horizontalGradient(listOf(CyberBlue.copy(alpha = glowAlpha * 0.3f), CyberPurple.copy(alpha = glowAlpha * 0.3f)))).blur(16.dp))
            }

            if (isProcessing) {
                // 取消按钮
                OutlinedButton(
                    onClick = onCancel,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, DangerRed.copy(alpha = 0.4f)),
                    colors = ButtonDefaults.outlinedButtonColors(containerColor = DangerRed.copy(alpha = 0.08f))
                ) {
                    Icon(Icons.Filled.Close, null, tint = DangerRed, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("取消加固", color = DangerRed, fontSize = 14.sp)
                }
            } else {
                Button(onClick = onClick, modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(18.dp), colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent),
                    contentPadding = PaddingValues(0.dp)) {
                    Box(modifier = Modifier.fillMaxSize().background(Brush.horizontalGradient(listOf(CyberBlue, Color(0xFF5B4DFF)))), contentAlignment = Alignment.Center) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Filled.Lock, null, tint = Color.White, modifier = Modifier.size(20.dp))
                            Spacer(Modifier.width(10.dp))
                            Text("开始加固", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color.White)
                        }
                    }
                }
            }
        }
    }
}

// ==================== 结果卡片 ====================
@Composable
fun ResultCard(result: ApkProcessor.ProcessResult) {
    val context = LocalContext.current
    Card(shape = RoundedCornerShape(20.dp), colors = CardDefaults.cardColors(containerColor = Color.Transparent),
        border = BorderStroke(1.dp, if (result.success) ElectricGreen.copy(alpha = 0.3f) else DangerRed.copy(alpha = 0.3f))) {
        Box(modifier = Modifier.fillMaxWidth().background(Brush.linearGradient(listOf(CardDark, CardDarkAlt))).padding(24.dp)) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(modifier = Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)).background(
                        if (result.success) ElectricGreen.copy(alpha = 0.1f) else DangerRed.copy(alpha = 0.1f)), contentAlignment = Alignment.Center) {
                        Icon(if (result.success) Icons.Filled.VerifiedUser else Icons.Filled.GppBad, null,
                            tint = if (result.success) ElectricGreen else DangerRed, modifier = Modifier.size(26.dp))
                    }
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(result.message, fontSize = 16.sp, fontWeight = FontWeight.Bold, color = if (result.success) ElectricGreen else DangerRed)
                        Text(if (result.success) "APK 已加固并签名，可直接安装" else "处理过程中出现错误", fontSize = 11.sp, color = TextDim)
                    }
                }
                if (result.details.isNotEmpty()) {
                    Spacer(Modifier.height(16.dp))
                    Box(modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(DeepBlue.copy(alpha = 0.5f)).padding(16.dp)) {
                        Text(result.details, fontSize = 12.sp, color = TextGray, lineHeight = 20.sp, fontFamily = FontFamily.Monospace)
                    }
                }
                if (result.success && result.outputPath != null) {
                    Spacer(Modifier.height(20.dp))
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        OutlinedButton(onClick = {
                            val file = File(result.outputPath!!)
                            if (file.exists()) {
                                val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
                                context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                                    type = "application/vnd.android.package-archive"; putExtra(Intent.EXTRA_STREAM, uri); addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                }, "分享加固后的 APK"))
                            }
                        }, modifier = Modifier.weight(1f).height(44.dp), shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, CyberBlue.copy(alpha = 0.3f)),
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = CyberBlue.copy(alpha = 0.05f))) {
                            Icon(Icons.Filled.Share, null, Modifier.size(18.dp), tint = CyberBlue); Spacer(Modifier.width(6.dp)); Text("分享", color = CyberBlue, fontSize = 13.sp)
                        }
                        OutlinedButton(onClick = {
                            val file = File(result.outputPath!!)
                            if (file.exists()) {
                                try {
                                    context.startActivity(Intent(Intent.ACTION_VIEW).apply {
                                        setDataAndType(FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file), "application/vnd.android.package-archive")
                                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                                    })
                                } catch (_: Exception) { Toast.makeText(context, "请在文件管理器中打开安装", Toast.LENGTH_SHORT).show() }
                            }
                        }, modifier = Modifier.weight(1f).height(44.dp), shape = RoundedCornerShape(12.dp),
                            border = BorderStroke(1.dp, ElectricGreen.copy(alpha = 0.3f)),
                            colors = ButtonDefaults.outlinedButtonColors(containerColor = ElectricGreen.copy(alpha = 0.05f))) {
                            Icon(Icons.Filled.InstallMobile, null, Modifier.size(18.dp), tint = ElectricGreen); Spacer(Modifier.width(6.dp)); Text("安装", color = ElectricGreen, fontSize = 13.sp)
                        }
                    }
                }
            }
        }
    }
}

// ==================== 底部 ====================
@Composable
fun FooterSection() {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Divider(Modifier.fillMaxWidth(0.6f).padding(vertical = 4.dp), color = CyberBlue.copy(alpha = 0.1f), thickness = 1.dp)
        Spacer(Modifier.height(16.dp))
        Text("四层加密架构", fontSize = 12.sp, color = TextDim, letterSpacing = 3.sp)
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth(0.8f), horizontalArrangement = Arrangement.SpaceEvenly) {
            listOf("XOR" to CyberBlue, "Base64" to CyberPurple, "AES-256" to CyberPink, "SHA256" to ElectricGreen).forEach { (name, color) ->
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(Modifier.size(8.dp).clip(CircleShape).background(color))
                    Spacer(Modifier.height(4.dp))
                    Text(name, fontSize = 9.sp, color = TextDim, letterSpacing = 1.sp)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Text("v3.0.0 · SecurityGuard", fontSize = 10.sp, color = TextDim.copy(alpha = 0.5f), letterSpacing = 2.sp)
    }
}