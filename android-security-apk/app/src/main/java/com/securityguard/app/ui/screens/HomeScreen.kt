package com.securityguard.app.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.securityguard.app.security.SecurityScanner
import com.securityguard.app.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    scanner: SecurityScanner
) {
    var report by remember { mutableStateOf<SecurityScanner.SecurityReport?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var expandedItem by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            Icons.Filled.Security,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Text(
                            text = "安全加固卫士",
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Primary,
                    titleContentColor = Color.White
                )
            )
        }
    ) { paddingValues ->
        if (report == null && !isScanning) {
            // 初始状态 - 显示欢迎界面
            WelcomeScreen(
                modifier = Modifier.padding(paddingValues),
                onStartScan = {
                    isScanning = true
                    // 模拟扫描延迟
                    kotlinx.coroutines.MainScope().also {
                        // 直接执行
                        report = scanner.performFullScan()
                        isScanning = false
                    }
                }
            )
        } else if (isScanning) {
            // 扫描中
            ScanningScreen(modifier = Modifier.padding(paddingValues))
        } else {
            // 扫描结果
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .background(SurfaceLight),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // 总体评分卡片
                item {
                    OverallScoreCard(report = report!!)
                }

                // 安全检测项
                item {
                    Text(
                        text = "安全检测项",
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp,
                        color = TextPrimary,
                        modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
                    )
                }

                val items = scanner.getSecurityItems(report!!)
                items(items) { item ->
                    SecurityItemCard(
                        item = item,
                        isExpanded = expandedItem == item.name,
                        onToggle = {
                            expandedItem = if (expandedItem == item.name) null else item.name
                        }
                    )
                }

                // 重新扫描按钮
                item {
                    Button(
                        onClick = {
                            expandedItem = null
                            isScanning = true
                            report = scanner.performFullScan()
                            isScanning = false
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                            .padding(top = 8.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Primary
                        )
                    ) {
                        Icon(Icons.Filled.Refresh, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("重新扫描", fontSize = 16.sp, fontWeight = FontWeight.Medium)
                    }
                }

                item { Spacer(modifier = Modifier.height(16.dp)) }
            }
        }
    }
}

@Composable
private fun WelcomeScreen(
    modifier: Modifier = Modifier,
    onStartScan: () -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(SurfaceLight)
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // 盾牌图标
        Box(
            modifier = Modifier
                .size(120.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(Primary.copy(alpha = 0.2f), Primary.copy(alpha = 0.05f))
                    )
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                Icons.Filled.Security,
                contentDescription = null,
                tint = Primary,
                modifier = Modifier.size(64.dp)
            )
        }

        Spacer(modifier = Modifier.height(32.dp))

        Text(
            text = "安全加固卫士",
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(12.dp))

        Text(
            text = "全面的安全检测，保护你的应用免受逆向破解、调试分析、Hook 注入等攻击",
            fontSize = 15.sp,
            color = TextSecondary,
            textAlign = TextAlign.Center,
            lineHeight = 22.sp
        )

        Spacer(modifier = Modifier.height(48.dp))

        Button(
            onClick = onStartScan,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Primary
            ),
            elevation = ButtonDefaults.buttonElevation(
                defaultElevation = 4.dp
            )
        ) {
            Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(24.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("开始安全扫描", fontSize = 18.sp, fontWeight = FontWeight.Medium)
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "扫描包括：签名校验 · 反调试 · Root检测 · 模拟器检测 · 加密状态 · Hook检测",
            fontSize = 12.sp,
            color = TextSecondary.copy(alpha = 0.7f),
            textAlign = TextAlign.Center
        )
    }
}

@Composable
private fun ScanningScreen(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(SurfaceLight),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            CircularProgressIndicator(
                modifier = Modifier.size(64.dp),
                color = Primary,
                strokeWidth = 5.dp
            )
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "正在进行安全扫描...",
                fontSize = 18.sp,
                fontWeight = FontWeight.Medium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "请稍候，正在检查各项安全指标",
                fontSize = 14.sp,
                color = TextSecondary
            )
        }
    }
}

@Composable
private fun OverallScoreCard(report: SecurityScanner.SecurityReport) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, shape = RoundedCornerShape(20.dp)),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = CardLight
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // 分数圆环
            Box(
                modifier = Modifier.size(140.dp),
                contentAlignment = Alignment.Center
            ) {
                CircularProgressIndicator(
                    progress = report.overallScore / 100f,
                    modifier = Modifier.size(140.dp),
                    color = when (report.overallStatus) {
                        SecurityScanner.SecurityStatus.SAFE -> SafeGreen
                        SecurityScanner.SecurityStatus.WARNING -> WarningOrange
                        SecurityScanner.SecurityStatus.DANGER -> DangerRed
                    },
                    strokeWidth = 10.dp,
                    trackColor = Color(0xFFE0E0E0)
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "${report.overallScore}",
                        fontSize = 40.sp,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary
                    )
                    Text(
                        text = "/ 100",
                        fontSize = 14.sp,
                        color = TextSecondary
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 状态标签
            val statusText = when (report.overallStatus) {
                SecurityScanner.SecurityStatus.SAFE -> "安全"
                SecurityScanner.SecurityStatus.WARNING -> "警告"
                SecurityScanner.SecurityStatus.DANGER -> "危险"
            }
            val statusColor = when (report.overallStatus) {
                SecurityScanner.SecurityStatus.SAFE -> SafeGreen
                SecurityScanner.SecurityStatus.WARNING -> WarningOrange
                SecurityScanner.SecurityStatus.DANGER -> DangerRed
            }
            val statusIcon = when (report.overallStatus) {
                SecurityScanner.SecurityStatus.SAFE -> Icons.Filled.CheckCircle
                SecurityScanner.SecurityStatus.WARNING -> Icons.Filled.Warning
                SecurityScanner.SecurityStatus.DANGER -> Icons.Filled.Dangerous
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    statusIcon,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = statusText,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    color = statusColor
                )
            }
        }
    }
}

@Composable
private fun SecurityItemCard(
    item: SecurityScanner.SecurityItem,
    isExpanded: Boolean,
    onToggle: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(2.dp, shape = RoundedCornerShape(16.dp))
            .clickable { onToggle() },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = CardLight
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                // 图标
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(
                            if (item.isPassed) SafeGreen.copy(alpha = 0.15f)
                            else DangerRed.copy(alpha = 0.15f)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        getIconByName(item.icon),
                        contentDescription = null,
                        tint = if (item.isPassed) SafeGreen else DangerRed,
                        modifier = Modifier.size(24.dp)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = item.name,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 16.sp,
                        color = TextPrimary
                    )
                    Text(
                        text = item.description,
                        fontSize = 13.sp,
                        color = TextSecondary,
                        maxLines = 1
                    )
                }

                // 状态指示
                Icon(
                    if (item.isPassed) Icons.Filled.CheckCircle else Icons.Filled.Cancel,
                    contentDescription = null,
                    tint = if (item.isPassed) SafeGreen else DangerRed,
                    modifier = Modifier.size(28.dp)
                )

                Spacer(modifier = Modifier.width(4.dp))

                Icon(
                    if (isExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                    contentDescription = null,
                    tint = TextSecondary,
                    modifier = Modifier.size(24.dp)
                )
            }

            // 展开详情
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                Column(modifier = Modifier.padding(top = 12.dp)) {
                    Divider(color = Color(0xFFEEEEEE))
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = item.details,
                        fontSize = 14.sp,
                        color = TextSecondary,
                        lineHeight = 20.sp
                    )
                }
            }
        }
    }
}

/**
 * 根据名称获取图标
 */
private fun getIconByName(name: String): ImageVector {
    return when (name) {
        "fingerprint" -> Icons.Filled.Fingerprint
        "bug_report" -> Icons.Filled.BugReport
        "security" -> Icons.Filled.Security
        "phone_android" -> Icons.Filled.PhoneAndroid
        "lock" -> Icons.Filled.Lock
        "flash_on" -> Icons.Filled.FlashOn
        else -> Icons.Filled.Shield
    }
}