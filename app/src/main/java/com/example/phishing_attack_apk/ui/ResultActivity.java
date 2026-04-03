package com.example.phishing_attack_apk.ui;

import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.example.phishing_attack_apk.R;
import com.example.phishing_attack_apk.model.ScanResult;


public class ResultActivity extends AppCompatActivity {

    // Keys for Intent extras — used by ScanActivity and SmsReceiver
    public static final String EXTRA_URL     = "result_url";
    public static final String EXTRA_SCORE   = "result_score";
    public static final String EXTRA_LEVEL   = "result_level";
    public static final String EXTRA_SOURCE  = "result_source";
    public static final String EXTRA_REASONS = "result_reasons";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        // ── Read Intent data ─────────────────────────────────────────
        String   url     = getIntent().getStringExtra(EXTRA_URL);
        int      score   = getIntent().getIntExtra(EXTRA_SCORE, 0);
        String   level   = getIntent().getStringExtra(EXTRA_LEVEL);
        String   source  = getIntent().getStringExtra(EXTRA_SOURCE);
        String[] reasons = getIntent().getStringArrayExtra(EXTRA_REASONS);

        // ── Views ────────────────────────────────────────────────────
        TextView tvUrl      = findViewById(R.id.tv_url);
        TextView tvBadge    = findViewById(R.id.tv_badge);
        TextView tvScore    = findViewById(R.id.tv_score);
        TextView tvSource   = findViewById(R.id.tv_source);
        LinearLayout llReasons = findViewById(R.id.ll_reasons);
        Button btnBack      = findViewById(R.id.btn_back);
        Button btnHistory   = findViewById(R.id.btn_history);
        Button btnReport    = findViewById(R.id.btn_report);
        tvUrl.setText(url != null ? url : "Unknown URL");

        tvScore.setText("Risk Score: " + score + " / 100");

        String sourceLabel = "Manual";
        if (ScanResult.SOURCE_QR.equals(source))  sourceLabel = "QR Code";
        if (ScanResult.SOURCE_SMS.equals(source))  sourceLabel = "SMS";
        tvSource.setText("Detected via: " + sourceLabel);
        if (ScanResult.LEVEL_SAFE.equals(level)) {
            tvBadge.setText("SAFE");
            tvBadge.setBackgroundColor(
                    ContextCompat.getColor(this, R.color.safe_green));
            tvBadge.setTextColor(Color.WHITE);

        } else if (ScanResult.LEVEL_SUSPICIOUS.equals(level)) {
            tvBadge.setText("SUSPICIOUS");
            tvBadge.setBackgroundColor(
                    ContextCompat.getColor(this, R.color.suspicious_yellow));
            tvBadge.setTextColor(Color.BLACK);

        } else {
            tvBadge.setText("PHISHING");
            tvBadge.setBackgroundColor(
                    ContextCompat.getColor(this, R.color.phishing_red));
            tvBadge.setTextColor(Color.WHITE);
        }

        llReasons.removeAllViews();
        if (reasons != null && reasons.length > 0) {
            for (String reason : reasons) {
                TextView tv = new TextView(this);
                tv.setText("• " + reason);
                tv.setTextSize(14f);
                tv.setPadding(0, 6, 0, 6);
                tv.setTextColor(ContextCompat.getColor(this, R.color.text_primary));
                llReasons.addView(tv);
            }
        } else {
            TextView tv = new TextView(this);
            tv.setText("• No issues detected");
            tv.setTextSize(14f);
            tv.setPadding(0, 6, 0, 6);
            llReasons.addView(tv);
        }
        btnBack.setOnClickListener(v -> finish());

        btnHistory.setOnClickListener(v -> {
            Intent intent = new Intent(this, HistoryActivity.class);
            startActivity(intent);
        });

        btnReport.setOnClickListener(v -> reportPhishing(url));
    }

    private void reportPhishing(String url) {
        if (url == null) return;
        try {
            String reportUrl = "https://www.phishtank.com/add_web_phish.php";
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(reportUrl));
            startActivity(intent);
            Toast.makeText(this,
                    "Opening PhishTank to report this URL",
                    Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this,
                    "Could not open browser",
                    Toast.LENGTH_SHORT).show();
        }
    }
}