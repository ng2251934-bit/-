package com.securityguard.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.securityguard.app.security.SecurityScanner
import com.securityguard.app.ui.screens.HomeScreen
import com.securityguard.app.ui.theme.SecurityGuardTheme

class MainActivity : ComponentActivity() {

    private lateinit var securityScanner: SecurityScanner

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        securityScanner = SecurityScanner(applicationContext)

        setContent {
            SecurityGuardTheme {
                HomeScreen(scanner = securityScanner)
            }
        }
    }
}