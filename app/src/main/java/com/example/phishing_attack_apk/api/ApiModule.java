package com.example.phishing_attack_apk.api;

import android.os.AsyncTask;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * ApiModule.java
 * Handles the Google Safe Browsing API v4 check.
 *
 * HOW TO GET YOUR API KEY:
 *  1. Go to https://console.cloud.google.com
 *  2. Create a new project
 *  3. Enable "Safe Browsing API"
 *  4. Go to Credentials → Create API Key
 *  5. Copy the key and paste below where it says YOUR_API_KEY_HERE
 *
 * Usage:
 *   ApiModule.checkUrl(url, new ApiModule.BlacklistCallback() {
 *       public void onResult(boolean isBlacklisted) {
 *           // update your ScanResult here
 *       }
 *       public void onError(String message) {
 *           // handle no internet etc.
 *       }
 *   });
 */
public class ApiModule {

    private static final String TAG = "ApiModule";

    // ── PASTE YOUR GOOGLE SAFE BROWSING API KEY HERE ─────────────────
    private static final String API_KEY = "YOUR_API_KEY_HERE";

    private static final String GSB_ENDPOINT =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=";

    // ── Callback interface ───────────────────────────────────────────
    public interface BlacklistCallback {
        void onResult(boolean isBlacklisted);
        void onError(String errorMessage);
    }

    /**
     * Async check — does NOT block the main thread.
     * Result delivered on the main thread via callback.
     */
    public static void checkUrl(String rawUrl, BlacklistCallback callback) {
        new BlacklistCheckTask(rawUrl, callback).execute();
    }

    // ── AsyncTask ────────────────────────────────────────────────────
    @SuppressWarnings("deprecation")
    private static class BlacklistCheckTask
            extends AsyncTask<Void, Void, Boolean> {

        private final String           url;
        private final BlacklistCallback callback;
        private String errorMessage = null;

        BlacklistCheckTask(String url, BlacklistCallback callback) {
            this.url      = url;
            this.callback = callback;
        }

        @Override
        protected Boolean doInBackground(Void... voids) {
            try {
                return callGoogleSafeBrowsing(url);
            } catch (Exception e) {
                Log.e(TAG, "GSB API error: " + e.getMessage());
                errorMessage = e.getMessage();
                return false; // on error, assume not blacklisted (fail-open)
            }
        }

        @Override
        protected void onPostExecute(Boolean isBlacklisted) {
            if (errorMessage != null) {
                callback.onError(errorMessage);
            } else {
                callback.onResult(isBlacklisted);
            }
        }
    }

    // ── Core API call ────────────────────────────────────────────────
    private static boolean callGoogleSafeBrowsing(String rawUrl) throws Exception {

        // Build request JSON body
        JSONObject requestBody = new JSONObject();

        JSONObject client = new JSONObject();
        client.put("clientId", "phishing-detector-student");
        client.put("clientVersion", "1.0");
        requestBody.put("client", client);

        JSONObject threatInfo = new JSONObject();

        JSONArray threatTypes = new JSONArray();
        threatTypes.put("MALWARE");
        threatTypes.put("SOCIAL_ENGINEERING");    // phishing
        threatTypes.put("UNWANTED_SOFTWARE");
        threatTypes.put("POTENTIALLY_HARMFUL_APPLICATION");
        threatInfo.put("threatTypes", threatTypes);

        JSONArray platformTypes = new JSONArray();
        platformTypes.put("ANY_PLATFORM");
        threatInfo.put("platformTypes", platformTypes);

        JSONArray threatEntryTypes = new JSONArray();
        threatEntryTypes.put("URL");
        threatInfo.put("threatEntryTypes", threatEntryTypes);

        JSONArray threatEntries = new JSONArray();
        JSONObject entry = new JSONObject();
        entry.put("url", rawUrl);
        threatEntries.put(entry);
        threatInfo.put("threatEntries", threatEntries);

        requestBody.put("threatInfo", threatInfo);

        // HTTP POST
        URL endpoint = new URL(GSB_ENDPOINT + API_KEY);
        HttpURLConnection conn = (HttpURLConnection) endpoint.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        OutputStream os = conn.getOutputStream();
        os.write(requestBody.toString().getBytes("UTF-8"));
        os.close();

        int responseCode = conn.getResponseCode();

        if (responseCode == 200) {
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();

            String responseStr = sb.toString();
            Log.d(TAG, "GSB response: " + responseStr);

            // If response has "matches", the URL is blacklisted
            JSONObject response = new JSONObject(responseStr);
            return response.has("matches") && response.getJSONArray("matches").length() > 0;
        }

        return false; // non-200 = treat as not blacklisted
    }
}