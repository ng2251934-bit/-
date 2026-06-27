package com.securityguard.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// 品牌色
val Primary = Color(0xFF1A73E8)
val PrimaryVariant = Color(0xFF1557B0)
val OnPrimary = Color(0xFFFFFFFF)

// 安全状态色
val SafeGreen = Color(0xFF34A853)
val WarningOrange = Color(0xFFFBBC04)
val DangerRed = Color(0xFFEA4335)

// 表面色
val SurfaceLight = Color(0xFFF8F9FA)
val SurfaceDark = Color(0xFF1E1E2E)
val CardLight = Color(0xFFFFFFFF)
val CardDark = Color(0xFF2D2D3F)

// 文字色
val TextPrimary = Color(0xFF202124)
val TextSecondary = Color(0xFF5F6368)
val TextOnDark = Color(0xFFE8EAED)

private val LightColorScheme = lightColorScheme(
    primary = Primary,
    onPrimary = OnPrimary,
    primaryContainer = Color(0xFFD2E3FC),
    secondary = Color(0xFF5F6368),
    onSecondary = Color.White,
    background = SurfaceLight,
    surface = CardLight,
    onBackground = TextPrimary,
    onSurface = TextPrimary,
    error = DangerRed,
    onError = Color.White
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF8AB4F8),
    onPrimary = Color(0xFF003A8C),
    primaryContainer = Color(0xFF1A237E),
    secondary = Color(0xFFBDBDBD),
    onSecondary = Color(0xFF333333),
    background = SurfaceDark,
    surface = CardDark,
    onBackground = TextOnDark,
    onSurface = TextOnDark,
    error = Color(0xFFEF5350),
    onError = Color.White
)

@Composable
fun SecurityGuardTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}