package com.securityguard.app.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// ========== 核心品牌色 ==========
val CyberBlue = Color(0xFF00D4FF)
val CyberPurple = Color(0xFF7B2FFF)
val CyberPink = Color(0xFFFF2D95)
val ElectricGreen = Color(0xFF00FF88)
val DeepBlue = Color(0xFF0A0E27)
val DarkNavy = Color(0xFF0D1129)
val SurfaceDark = Color(0xFF131736)
val CardDark = Color(0xFF181C3D)
val CardDarkAlt = Color(0xFF1C2050)
val TextWhite = Color(0xFFE8ECFF)
val TextGray = Color(0xFF8890B5)
val TextDim = Color(0xFF5A6080)
val SuccessGreen = Color(0xFF00E676)
val DangerRed = Color(0xFFFF3D5A)
val WarningOrange = Color(0xFFFFA726)
val Amber = Color(0xFFFFD740)

// ========== 渐变色 ==========
val GradientBlue = listOf(Color(0xFF00D4FF), Color(0xFF007BFF))
val GradientPurple = listOf(Color(0xFF7B2FFF), Color(0xFF3D5AFE))
val GradientPink = listOf(Color(0xFFFF2D95), Color(0xFFFF0055))
val GradientGreen = listOf(Color(0xFF00FF88), Color(0xFF00C853))
val GradientDark = listOf(Color(0xFF0D1129), Color(0xFF131736), Color(0xFF0A0E27))
val GradientCard = listOf(Color(0xFF181C3D), Color(0xFF151838))

private val CyberDarkColorScheme = darkColorScheme(
    primary = CyberBlue,
    onPrimary = Color(0xFF001A33),
    primaryContainer = Color(0xFF003366),
    onPrimaryContainer = Color(0xFF80D8FF),
    secondary = CyberPurple,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF2A1050),
    onSecondaryContainer = Color(0xFFD1C4FF),
    tertiary = CyberPink,
    onTertiary = Color.White,
    background = DeepBlue,
    onBackground = TextWhite,
    surface = SurfaceDark,
    onSurface = TextWhite,
    surfaceVariant = CardDark,
    onSurfaceVariant = TextGray,
    error = DangerRed,
    onError = Color.White,
    outline = Color(0xFF2A2F55)
)

@Composable
fun SecurityGuardTheme(
    darkTheme: Boolean = true,
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = CyberDarkColorScheme,
        typography = Typography(),
        content = content
    )
}