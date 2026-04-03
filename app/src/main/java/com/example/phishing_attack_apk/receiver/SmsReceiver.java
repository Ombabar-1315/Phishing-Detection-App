package com.example.phishing_attack_apk.receiver;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.provider.Telephony;
import android.telephony.SmsMessage;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.example.phishing_attack_apk.R;
import com.example.phishing_attack_apk.engine.SecurityEngine;
import com.example.phishing_attack_apk.engine.UrlAnalyzer;
import com.example.phishing_attack_apk.model.ScanResult;
import com.example.phishing_attack_apk.ui.ResultActivity;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SmsReceiver extends BroadcastReceiver {

    private static final String TAG          = "SmsReceiver";
    private static final String CHANNEL_ID   = "phishing_alert_channel";
    private static final String CHANNEL_NAME = "Phishing Alerts";
    private static final int    NOTIF_ID     = 1001;

    @Override
    public void onReceive(Context context, Intent intent) {

        Log.d(TAG, "onReceive triggered — action: " + intent.getAction());

        if (!Telephony.Sms.Intents.SMS_RECEIVED_ACTION.equals(intent.getAction())) {
            Log.d(TAG, "Not an SMS intent, ignoring.");
            return;
        }

        // ── Extract SMS messages from intent ─────────────────────────
        SmsMessage[] messages = null;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            messages = Telephony.Sms.Intents.getMessagesFromIntent(intent);
        } else {
            Bundle bundle = intent.getExtras();
            if (bundle != null) {
                Object[] pdus = (Object[]) bundle.get("pdus");
                String format = bundle.getString("format");
                if (pdus != null) {
                    messages = new SmsMessage[pdus.length];
                    for (int i = 0; i < pdus.length; i++) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            messages[i] = SmsMessage.createFromPdu((byte[]) pdus[i], format);
                        } else {
                            messages[i] = SmsMessage.createFromPdu((byte[]) pdus[i]);
                        }
                    }
                }
            }
        }

        if (messages == null || messages.length == 0) {
            Log.d(TAG, "No messages extracted from intent.");
            return;
        }

        // ── Build full SMS body from all parts ────────────────────────
        StringBuilder fullBody = new StringBuilder();
        for (SmsMessage msg : messages) {
            if (msg != null && msg.getMessageBody() != null) {
                fullBody.append(msg.getMessageBody());
            }
        }

        String body = fullBody.toString().trim();
        Log.d(TAG, "SMS body received: " + body);

        if (body.isEmpty()) {
            Log.d(TAG, "Empty SMS body, ignoring.");
            return;
        }

        // ── Extract URLs from SMS body ────────────────────────────────
        String[] urls = UrlAnalyzer.extractUrlsFromText(body);
        Log.d(TAG, "URLs found in SMS: " + urls.length);

        if (urls.length == 0) {
            Log.d(TAG, "No URLs found in SMS.");
            return;
        }

        // ── Analyze each URL in background thread ─────────────────────
        // Use pending result to keep receiver alive during async work
        final PendingResult pendingResult = goAsync();
        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.execute(() -> {
            try {
                for (String url : urls) {
                    Log.d(TAG, "Analyzing URL: " + url);
                    ScanResult result = SecurityEngine.analyze(url, ScanResult.SOURCE_SMS);
                    Log.d(TAG, "Result: " + result.getRiskLevel() + " score: " + result.getRiskScore());

                    if (!result.isSafe()) {
                        showNotification(context, result);
                        break;
                    }
                }
            } finally {
                pendingResult.finish();
            }
        });

        executor.shutdown();
    }

    // ── Show push notification ────────────────────────────────────────
    private void showNotification(Context context, ScanResult result) {

        NotificationManager manager =
                (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);

        if (manager == null) {
            Log.e(TAG, "NotificationManager is null");
            return;
        }

        // Create channel for Android 8.0+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_HIGH
            );
            channel.setDescription("Alerts when phishing link detected in SMS");
            channel.enableVibration(true);
            channel.setShowBadge(true);
            manager.createNotificationChannel(channel);
        }

        // Intent to open ResultActivity when notification tapped
        Intent resultIntent = new Intent(context, ResultActivity.class);
        resultIntent.putExtra(ResultActivity.EXTRA_URL,     result.getUrl());
        resultIntent.putExtra(ResultActivity.EXTRA_SCORE,   result.getRiskScore());
        resultIntent.putExtra(ResultActivity.EXTRA_LEVEL,   result.getRiskLevel());
        resultIntent.putExtra(ResultActivity.EXTRA_SOURCE,  result.getSourceType());
        resultIntent.putExtra(ResultActivity.EXTRA_REASONS,
                result.getReasons().toArray(new String[0]));
        resultIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                context,
                0,
                resultIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        String title   = result.isPhishing()
                ? "Phishing link detected in SMS!"
                : "Suspicious link found in SMS";
        String message = result.isPhishing()
                ? "WARNING: Do NOT open — " + result.getUrl()
                : "Suspicious link found. Tap to review.";

        NotificationCompat.Builder builder =
                new NotificationCompat.Builder(context, CHANNEL_ID)
                        .setSmallIcon(R.drawable.ic_warning)
                        .setContentTitle(title)
                        .setContentText(message)
                        .setStyle(new NotificationCompat.BigTextStyle().bigText(message))
                        .setPriority(NotificationCompat.PRIORITY_MAX)
                        .setAutoCancel(true)
                        .setVibrate(new long[]{0, 500, 200, 500})
                        .setContentIntent(pendingIntent);

        manager.notify(NOTIF_ID, builder.build());
        Log.d(TAG, "Notification shown for: " + result.getUrl());
    }
}