package com.example.phishing_attack_apk.ui;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanOptions;
import com.example.phishing_attack_apk.R;
import com.example.phishing_attack_apk.engine.UrlAnalyzer;
import com.example.phishing_attack_apk.model.ScanResult;

public class MainActivity extends AppCompatActivity {

    private final ActivityResultLauncher<ScanOptions> qrScanLauncher =
            registerForActivityResult(new ScanContract(), result -> {
                if (result.getContents() == null) {
                    Toast.makeText(this, "Scan cancelled", Toast.LENGTH_SHORT).show();
                    return;
                }
                handleQrResult(result.getContents());
            });

    private final ActivityResultLauncher<String> cameraPermLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.RequestPermission(), granted -> {
                        if (granted) {
                            launchQrScanner();
                        } else {
                            Toast.makeText(this,
                                    "Camera permission needed for QR scanning",
                                    Toast.LENGTH_LONG).show();
                        }
                    });

    // Request multiple SMS permissions at once
    private final ActivityResultLauncher<String[]> smsPermLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.RequestMultiplePermissions(), result -> {
                        Boolean receiveSms = result.get(Manifest.permission.RECEIVE_SMS);
                        Boolean readSms    = result.get(Manifest.permission.READ_SMS);
                        if (Boolean.TRUE.equals(receiveSms) && Boolean.TRUE.equals(readSms)) {
                            Toast.makeText(this,
                                    "SMS Auto-Scan is now active!",
                                    Toast.LENGTH_LONG).show();
                        } else {
                            Toast.makeText(this,
                                    "SMS permission denied — auto-scan won't work",
                                    Toast.LENGTH_LONG).show();
                        }
                    });

    // Notification permission launcher (Android 13+)
    private final ActivityResultLauncher<String> notifPermLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.RequestPermission(), granted -> {
                    });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button btnManual    = findViewById(R.id.btn_manual_url);
        Button btnQr        = findViewById(R.id.btn_scan_qr);
        Button btnClipboard = findViewById(R.id.btn_clipboard);
        Button btnHistory   = findViewById(R.id.btn_history);

        btnManual.setOnClickListener(v ->
                startActivity(new Intent(this, ScanActivity.class)));

        btnQr.setOnClickListener(v -> requestCameraAndScan());

        btnClipboard.setOnClickListener(v -> handleClipboard());

        btnHistory.setOnClickListener(v ->
                startActivity(new Intent(this, HistoryActivity.class)));

        // Request all needed permissions on launch
        requestAllPermissions();
    }

    // ── QR Scanner ───────────────────────────────────────────────────
    private void requestCameraAndScan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
                == PackageManager.PERMISSION_GRANTED) {
            launchQrScanner();
        } else {
            cameraPermLauncher.launch(Manifest.permission.CAMERA);
        }
    }

    private void launchQrScanner() {
        ScanOptions options = new ScanOptions();
        options.setPrompt("Point camera at a QR code");
        options.setBeepEnabled(true);
        options.setOrientationLocked(false);
        qrScanLauncher.launch(options);
    }

    private void handleQrResult(String scannedText) {
        String url = null;
        if (scannedText.startsWith("http://") || scannedText.startsWith("https://")) {
            url = scannedText;
        } else {
            String[] extracted = UrlAnalyzer.extractUrlsFromText(scannedText);
            if (extracted.length > 0) url = extracted[0];
        }
        if (url != null) {
            Intent intent = new Intent(this, ScanActivity.class);
            intent.putExtra(ScanActivity.EXTRA_URL,    url);
            intent.putExtra(ScanActivity.EXTRA_SOURCE, ScanResult.SOURCE_QR);
            startActivity(intent);
        } else {
            Toast.makeText(this,
                    "QR content: " + scannedText + "\n(No URL found)",
                    Toast.LENGTH_LONG).show();
        }
    }

    // ── Clipboard ────────────────────────────────────────────────────
    private void handleClipboard() {
        ClipboardManager clipboard =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip()) {
            Toast.makeText(this, "Clipboard is empty", Toast.LENGTH_SHORT).show();
            return;
        }
        ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
        String text = item.getText() != null ? item.getText().toString() : "";
        if (text.isEmpty()) {
            Toast.makeText(this, "Nothing copied", Toast.LENGTH_SHORT).show();
            return;
        }
        String url = null;
        if (text.startsWith("http://") || text.startsWith("https://")) {
            url = text;
        } else {
            String[] extracted = UrlAnalyzer.extractUrlsFromText(text);
            if (extracted.length > 0) url = extracted[0];
        }
        if (url != null) {
            Intent intent = new Intent(this, ScanActivity.class);
            intent.putExtra(ScanActivity.EXTRA_URL,    url);
            intent.putExtra(ScanActivity.EXTRA_SOURCE, ScanResult.SOURCE_MANUAL);
            startActivity(intent);
        } else {
            Toast.makeText(this, "No URL found in clipboard", Toast.LENGTH_SHORT).show();
        }
    }

    // ── Permissions ──────────────────────────────────────────────────
    private void requestAllPermissions() {

        // SMS permissions — both RECEIVE and READ needed
        boolean hasSmsPermission =
                ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
                        == PackageManager.PERMISSION_GRANTED
                        && ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS)
                        == PackageManager.PERMISSION_GRANTED;

        if (!hasSmsPermission) {
            smsPermLauncher.launch(new String[]{
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_SMS
            });
        }

        // Notification permission — Android 13+ (API 33) only
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this,
                    Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS);
            }
        }
    }
}