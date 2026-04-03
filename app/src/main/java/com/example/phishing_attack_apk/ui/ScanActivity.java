package com.example.phishing_attack_apk.ui;

import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.phishing_attack_apk.R;
import com.example.phishing_attack_apk.api.ApiModule;
import com.example.phishing_attack_apk.database.ScanDatabase;
import com.example.phishing_attack_apk.database.ScanEntity;
import com.example.phishing_attack_apk.engine.SecurityEngine;
import com.example.phishing_attack_apk.model.ScanResult;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * ScanActivity.java
 * Accepts a URL (manually typed, or pre-filled from QR / clipboard),
 * runs the full security check, then opens ResultActivity.
 *
 * The scanning happens in 2 stages:
 *   Stage 1 (instant):  offline checks via SecurityEngine.analyze()
 *   Stage 2 (async):    Google Safe Browsing API check via ApiModule
 * Both stages complete before ResultActivity is opened.
 */
public class ScanActivity extends AppCompatActivity {

    public static final String EXTRA_URL    = "extra_url";
    public static final String EXTRA_SOURCE = "extra_source";

    private EditText    etUrl;
    private Button      btnScan;
    private ProgressBar progressBar;

    private ExecutorService executor = Executors.newSingleThreadExecutor();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_scan);

        etUrl       = findViewById(R.id.et_url);
        btnScan     = findViewById(R.id.btn_scan);
        progressBar = findViewById(R.id.progress_bar);

        // If URL was passed from QR/clipboard, pre-fill the field
        String prefilledUrl    = getIntent().getStringExtra(EXTRA_URL);
        String prefilledSource = getIntent().getStringExtra(EXTRA_SOURCE);

        if (!TextUtils.isEmpty(prefilledUrl)) {
            etUrl.setText(prefilledUrl);
            // Auto-scan if URL came from QR or clipboard
            if (prefilledSource != null) {
                startScan(prefilledUrl, prefilledSource);
            }
        }

        btnScan.setOnClickListener(v -> {
            String url = etUrl.getText().toString().trim();
            if (TextUtils.isEmpty(url)) {
                Toast.makeText(this, "Please enter a URL", Toast.LENGTH_SHORT).show();
                return;
            }
            // Add https:// if user forgot to type it
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://" + url;
                etUrl.setText(url);
            }
            startScan(url, ScanResult.SOURCE_MANUAL);
        });
    }

    private void startScan(String url, String sourceType) {
        // Show progress, disable button
        showLoading(true);

        final String finalUrl = url;
        final String finalSource = sourceType;

        // Stage 1: Run offline checks in background
        executor.execute(() -> {
            ScanResult result = SecurityEngine.analyze(finalUrl, finalSource);

            // Stage 2: Google Safe Browsing API check
            ApiModule.checkUrl(finalUrl, new ApiModule.BlacklistCallback() {
                @Override
                public void onResult(boolean isBlacklisted) {
                    SecurityEngine.applyBlacklistResult(result, isBlacklisted);
                    finishScan(result);
                }

                @Override
                public void onError(String errorMessage) {
                    // API failed — proceed with offline results only
                    result.addReason("Note: Blacklist check unavailable (no internet)");
                    finishScan(result);
                }
            });
        });
    }

    /** Called after all checks complete — saves to DB and opens ResultActivity */
    private void finishScan(ScanResult result) {
        // Save to Room database (on background thread)
        executor.execute(() -> {
            ScanDatabase db = ScanDatabase.getInstance(getApplicationContext());
            db.scanDao().insertScan(ScanEntity.fromScanResult(result));
        });

        // Open ResultActivity on main thread
        runOnUiThread(() -> {
            showLoading(false);
            openResultActivity(result);
        });
    }

    private void openResultActivity(ScanResult result) {
        Intent intent = new Intent(this, ResultActivity.class);
        intent.putExtra(ResultActivity.EXTRA_URL,     result.getUrl());
        intent.putExtra(ResultActivity.EXTRA_SCORE,   result.getRiskScore());
        intent.putExtra(ResultActivity.EXTRA_LEVEL,   result.getRiskLevel());
        intent.putExtra(ResultActivity.EXTRA_SOURCE,  result.getSourceType());
        intent.putExtra(ResultActivity.EXTRA_REASONS,
                result.getReasons().toArray(new String[0]));
        startActivity(intent);
    }

    private void showLoading(boolean loading) {
        progressBar.setVisibility(loading ? View.VISIBLE : View.GONE);
        btnScan.setEnabled(!loading);
        btnScan.setText(loading ? "Scanning..." : "Scan");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}