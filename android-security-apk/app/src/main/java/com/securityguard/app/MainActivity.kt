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
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.securityguard.app.protector.ApkProcessor
import com.securityguard.app.ui.theme.*
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProtectorScreen() {
    val context = LocalContext.current
    var selectedApk by remember { mutableStateOf<Uri?>(null) }
    var apkInfo by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var encryptionLevel by remember { mutableIntStateOf(3) }
    var isProcessing by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<ApkProcessor.ProcessResult?>(null) }
    var showPermissionDialog by remember { mutableStateOf(false) }

    val apkPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            // 获取持久化权限
            context.contentResolver.takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
            selectedApk = uri
            // 获取 APK 信息
            val path = uri.path ?: ""
            apkInfo = ApkProcessor.getApkInfo(path)
        }
    }

    // 检查存储权限
    LaunchedEffect(Unit) {
        if (!Environment.isExternalStorageManager()) {
            showPermissionDialog = true
        }
    }

    if (showPermissionDialog) {
        AlertDialog(
            onDismissRequest = { showPermissionDialog = false },
            title = { Text("需要存储权限") },
            text = { Text("加固 APK 需要访问存储权限来读取和保存文件") },
            confirmButton = {
                TextButton(onClick = {
                    showPermissionDialog = false
                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    intent.data = Uri.parse("package:${context.packageName}")
                    context.startActivity(intent)
                }) {
                    Text("去设置")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPermissionDialog = false }) {
                    Text("取消")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.Shield, null, tint = Color.White)
                        Spacer(Modifier.width(10.dp))
                        Text("APK 加固卫士", fontWeight = FontWeight.Bold)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Primary)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .background(SurfaceLight)
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // 标题区
            Text(
                "保护你的 APK",
                fontSize = 26.sp, fontWeight = FontWeight.Bold, color = TextPrimary
            )
            Text(
                "多层加密加固，防止逆向破解",
                fontSize = 14.sp, color = TextSecondary,
                modifier = Modifier.padding(top = 6.dp, bottom = 24.dp)
            )

            // 选择 APK 按钮
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { apkPicker.launch(arrayOf("application/vnd.android.package-archive")) },
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (selectedApk != null) SafeGreen.copy(alpha = 0.08f) 
                                     else CardLight
                ),
                border = if (selectedApk == null) 
                    androidx.compose.foundation.BorderStroke(2.dp, Primary.copy(alpha = 0.3f))
                else null
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        if (selectedApk != null) Icons.Filled.CheckCircle else Icons.Filled.Add,
                        null,
                        tint = if (selectedApk != null) SafeGreen else Primary,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        if (selectedApk != null) apkInfo["文件名"] ?: "已选择" else "选择 APK 文件",
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextPrimary
                    )
                    if (selectedApk != null) {
                        Spacer(Modifier.height(8.dp))
                        apkInfo.forEach { (k, v) ->
                            Text(
                                "$k: $v",
                                fontSize = 13.sp, color = TextSecondary
                            )
                        }
                    }
                }
            }

            // 加密强度
            if (selectedApk != null) {
                Spacer(Modifier.height(24.dp))

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = CardLight)
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("加密强度", fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        Spacer(Modifier.height(12.dp))

                        val levels = listOf(
                            Triple(1, "基础", "AES-256-CBC 加密"),
                            Triple(2, "标准", "AES + Base64 混淆"),
                            Triple(3, "深度", "XOR + Base64 + AES + 完整性校验")
                        )

                        levels.forEach { (level, name, desc) ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(
                                        if (level == encryptionLevel) Primary.copy(alpha = 0.1f)
                                        else Color.Transparent
                                    )
                                    .clickable { encryptionLevel = level }
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = level == encryptionLevel,
                                    onClick = { encryptionLevel = level },
                                    colors = RadioButtonDefaults.colors(selectedColor = Primary)
                                )
                                Spacer(Modifier.width(8.dp))
                                Column {
                                    Text(name, fontWeight = FontWeight.Medium, fontSize = 15.sp)
                                    Text(desc, fontSize = 12.sp, color = TextSecondary)
                                }
                            }
                        }
                    }
                }

                Spacer(Modifier.height(24.dp))

                // 加固按钮
                Button(
                    onClick = {
                        isProcessing = true
                        result = null
                        val outputDir = context.getExternalFilesDir("protected")?.absolutePath
                            ?: context.filesDir.absolutePath
                        val path = selectedApk?.let { uri ->
                            // 复制到临时文件
                            val tmpFile = File(context.cacheDir, "input.apk")
                            context.contentResolver.openInputStream(uri)?.use { input ->
                                tmpFile.outputStream().use { output ->
                                    input.copyTo(output)
                                }
                            }
                            tmpFile.absolutePath
                        }
                        if (path != null) {
                            val options = ApkProcessor.ProtectOptions(
                                enableDexEncryption = true,
                                encryptionLevel = encryptionLevel
                            )
                            result = ApkProcessor.protectApk(context, path, outputDir, options)
                        }
                        isProcessing = false
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = Primary),
                    enabled = !isProcessing
                ) {
                    if (isProcessing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(10.dp))
                        Text("正在加固...", fontSize = 16.sp)
                    } else {
                        Icon(Icons.Filled.Lock, null)
                        Spacer(Modifier.width(8.dp))
                        Text("开始加固", fontSize = 16.sp, fontWeight = FontWeight.Medium)
                    }
                }
            }

            // 结果
            if (result != null) {
                Spacer(Modifier.height(20.dp))

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = if (result!!.success)
                            SafeGreen.copy(alpha = 0.08f) else DangerRed.copy(alpha = 0.08f)
                    )
                ) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                if (result!!.success) Icons.Filled.CheckCircle else Icons.Filled.Error,
                                null,
                                tint = if (result!!.success) SafeGreen else DangerRed
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                result!!.message,
                                fontWeight = FontWeight.Bold,
                                fontSize = 16.sp,
                                color = if (result!!.success) SafeGreen else DangerRed
                            )
                        }

                        if (result!!.details.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                result!!.details,
                                fontSize = 13.sp,
                                color = TextSecondary,
                                lineHeight = 20.sp
                            )
                        }

                        if (result!!.success && result!!.outputPath != null) {
                            Spacer(Modifier.height(12.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = {
                                        val file = File(result!!.outputPath!!)
                                        val uri = FileProvider.getUriForFile(
                                            context, "${context.packageName}.fileprovider", file
                                        )
                                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                            type = "application/vnd.android.package-archive"
                                            putExtra(Intent.EXTRA_STREAM, uri)
                                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        }
                                        context.startActivity(Intent.createChooser(shareIntent, "分享加固APK"))
                                    },
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Icon(Icons.Filled.Share, null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text("分享")
                                }

                                OutlinedButton(
                                    onClick = {
                                        result = null
                                        selectedApk = null
                                        apkInfo = emptyMap()
                                    },
                                    shape = RoundedCornerShape(12.dp)
                                ) {
                                    Icon(Icons.Filled.Refresh, null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.width(6.dp))
                                    Text("再来一个")
                                }
                            }
                        }
                    }
                }
            }

            // 底部说明
            Spacer(Modifier.height(32.dp))
            Text(
                "加密说明：\n"
                    + "• 深度加密 = XOR混淆 + 自定义Base64 + AES-256-CBC + SHA256校验\n"
                    + "• 加固后的 APK 需要重新签名才能安装\n"
                    + "• 仅用于保护你自己的应用",
                fontSize = 12.sp,
                color = TextSecondary.copy(alpha = 0.7f),
                textAlign = TextAlign.Center,
                lineHeight = 18.sp
            )
        }
    }
}