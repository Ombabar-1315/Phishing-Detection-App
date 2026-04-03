package com.example.phishing_attack_apk.engine;

import com.example.phishing_attack_apk.model.ScanResult;

/**
 * SecurityEngine.java
 * The brain of the app.
 * Runs all checks on a URL and builds a ScanResult with score + reasons.
 *
 * Scoring table:
 *  ┌──────────────────────────────┬────────┐
 *  │ Check                        │ Points │
 *  ├──────────────────────────────┼────────┤
 *  │ No HTTPS (uses HTTP)         │  +20   │
 *  │ Suspicious keyword in URL    │  +20   │
 *  │ Risky TLD (.xyz, .top etc.)  │  +20   │
 *  │ IP address instead of domain │  +20   │
 *  │ Lookalike of trusted brand   │  +20   │
 *  │ Excessive subdomains (>2)    │  +10   │
 *  │ URL excessively long (>75ch) │  +10   │
 *  │ Blacklisted (API check)      │  +30   │ (added async by ApiModule)
 *  └──────────────────────────────┴────────┘
 *  Max offline score = 120, capped to 100.
 *
 * Usage:
 *   ScanResult result = SecurityEngine.analyze(url, ScanResult.SOURCE_MANUAL);
 *   // result.getRiskLevel() → "SAFE" / "SUSPICIOUS" / "PHISHING"
 */
public class SecurityEngine {

    // ── Score weights ────────────────────────────────────────────────
    private static final int SCORE_NO_HTTPS         = 20;
    private static final int SCORE_SUSPICIOUS_WORD  = 20;
    private static final int SCORE_RISKY_TLD        = 20;
    private static final int SCORE_IP_ADDRESS       = 20;
    private static final int SCORE_LOOKALIKE_BRAND  = 20;
    private static final int SCORE_MANY_SUBDOMAINS  = 10;
    private static final int SCORE_LONG_URL         = 10;
    public  static final int SCORE_BLACKLISTED      = 30; // used by ApiModule

    /**
     * Main method — runs all offline checks synchronously.
     * Call this from a background thread (AsyncTask / ExecutorService).
     *
     * @param rawUrl     the URL string to analyze
     * @param sourceType ScanResult.SOURCE_MANUAL / SOURCE_QR / SOURCE_SMS
     * @return ScanResult with score, level and reasons populated
     */
    public static ScanResult analyze(String rawUrl, String sourceType) {

        ScanResult result = new ScanResult(rawUrl, sourceType);

        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            result.addReason("Empty URL provided");
            result.addScore(100);
            result.computeRiskLevel();
            return result;
        }

        String domain = UrlAnalyzer.extractDomain(rawUrl);

        // ── Check 1: HTTPS ───────────────────────────────────────────
        if (!UrlAnalyzer.isHttps(rawUrl)) {
            result.addScore(SCORE_NO_HTTPS);
            result.addReason("No HTTPS — connection is not encrypted");
        }

        // ── Check 2: Suspicious keywords ─────────────────────────────
        if (UrlAnalyzer.hasSuspiciousKeywords(rawUrl)) {
            result.addScore(SCORE_SUSPICIOUS_WORD);
            String kw = UrlAnalyzer.getMatchedKeyword(rawUrl);
            result.addReason("Suspicious keyword found: \"" + kw + "\"");
        }

        // ── Check 3: Risky TLD ───────────────────────────────────────
        if (UrlAnalyzer.hasRiskyTld(domain)) {
            result.addScore(SCORE_RISKY_TLD);
            result.addReason("High-risk domain extension (e.g. .xyz, .top, .tk)");
        }

        // ── Check 4: IP address used instead of domain ───────────────
        if (UrlAnalyzer.hasIpAddress(rawUrl)) {
            result.addScore(SCORE_IP_ADDRESS);
            result.addReason("URL uses IP address instead of domain name");
        }

        // ── Check 5: Lookalike / brand impersonation ─────────────────
        if (UrlAnalyzer.isLookalikeOfTrustedBrand(domain)) {
            result.addScore(SCORE_LOOKALIKE_BRAND);
            result.addReason("Domain imitates a trusted brand (possible spoofing)");
        }

        // ── Check 6: Too many subdomains ─────────────────────────────
        int subdomainCount = UrlAnalyzer.countSubdomains(domain);
        if (subdomainCount > 2) {
            result.addScore(SCORE_MANY_SUBDOMAINS);
            result.addReason("Unusually deep subdomains (" + subdomainCount + " levels)");
        }

        // ── Check 7: Excessively long URL ────────────────────────────
        if (UrlAnalyzer.isExcessivelyLong(rawUrl)) {
            result.addScore(SCORE_LONG_URL);
            result.addReason("URL is unusually long (often hides real destination)");
        }

        // ── Compute final level ───────────────────────────────────────
        // Note: blacklist check (+30) is added separately by ApiModule
        // after this method returns, then computeRiskLevel() is called again.
        result.computeRiskLevel();

        return result;
    }

    /**
     * Apply the blacklist API result to an existing ScanResult.
     * Called by ApiModule after the async Google Safe Browsing check.
     *
     * @param result       the ScanResult from analyze()
     * @param isBlacklisted true if GSB or PhishTank flagged the URL
     */
    public static void applyBlacklistResult(ScanResult result, boolean isBlacklisted) {
        if (isBlacklisted) {
            result.addScore(SCORE_BLACKLISTED);
            result.addReason("URL found in blacklist (Google Safe Browsing)");
        }
        // Recompute level now that blacklist score is added
        result.computeRiskLevel();
    }
}