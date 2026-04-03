package com.example.phishing_attack_apk.engine;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * UrlAnalyzer.java
 * Responsible for breaking a raw URL string into useful parts.
 * All methods are static — no need to create an instance.
 *
 * Used by SecurityEngine before running checks.
 */
public class UrlAnalyzer {

    // ── Suspicious keyword list ──────────────────────────────────────
    // These words commonly appear in phishing URLs
    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
            "login", "signin", "verify", "update", "secure", "account",
            "banking", "payment", "confirm", "password", "credential",
            "webscr", "cmd=", "dispatch", "suspended", "limited",
            "unusual", "access", "recover", "unlock", "validate",
            "alert", "notification", "urgent", "immediately"
    );

    // ── Risky TLD list ───────────────────────────────────────────────
    // These top-level domains are heavily abused by phishers
    private static final List<String> RISKY_TLDS = Arrays.asList(
            ".xyz", ".top", ".icu", ".club", ".online", ".site",
            ".live", ".work", ".click", ".link", ".gq", ".ml",
            ".cf", ".ga", ".tk"
    );

    // ── Trusted brands (for lookalike detection) ─────────────────────
    private static final List<String> TRUSTED_BRANDS = Arrays.asList(
            "google", "facebook", "paypal", "amazon", "apple",
            "microsoft", "netflix", "instagram", "twitter", "linkedin",
            "sbi", "hdfc", "icici", "axis", "kotak",        // Indian banks
            "paytm", "phonepe", "gpay", "upi"               // Indian payment apps
    );

    // ── URL regex — finds http/https links in plain text (SMS use) ───
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
    );

    // ═══════════════════════════════════════════════════════════════
    //  PUBLIC METHODS
    // ═══════════════════════════════════════════════════════════════

    /**
     * Extract the domain from a full URL.
     * e.g.  "https://paypal-login.xyz/verify" → "paypal-login.xyz"
     */
    public static String extractDomain(String rawUrl) {
        try {
            URL url = new URL(rawUrl);
            return url.getHost().toLowerCase();
        } catch (MalformedURLException e) {
            // Fallback: strip protocol manually
            String domain = rawUrl.replaceAll("https?://", "");
            int slash = domain.indexOf('/');
            return slash > 0 ? domain.substring(0, slash) : domain;
        }
    }

    /**
     * Returns true if URL uses HTTPS.
     * HTTP without S is less secure — adds risk score.
     */
    public static boolean isHttps(String rawUrl) {
        return rawUrl != null && rawUrl.toLowerCase().startsWith("https://");
    }

    /**
     * Returns true if URL or domain contains any suspicious keyword.
     * Checks the full URL so query params like ?cmd=login are caught too.
     */
    public static boolean hasSuspiciousKeywords(String rawUrl) {
        if (rawUrl == null) return false;
        String lower = rawUrl.toLowerCase();
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lower.contains(keyword)) return true;
        }
        return false;
    }

    /**
     * Returns the matched suspicious keyword for use in reason string.
     * Returns null if no match found.
     */
    public static String getMatchedKeyword(String rawUrl) {
        if (rawUrl == null) return null;
        String lower = rawUrl.toLowerCase();
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (lower.contains(keyword)) return keyword;
        }
        return null;
    }

    /**
     * Returns true if the TLD is in the risky list.
     * e.g.  "secure-hdfc.xyz" → true
     */
    public static boolean hasRiskyTld(String domain) {
        if (domain == null) return false;
        String lower = domain.toLowerCase();
        for (String tld : RISKY_TLDS) {
            if (lower.endsWith(tld)) return true;
        }
        return false;
    }

    /**
     * Detects lookalike attacks — domain contains a trusted brand name
     * but is NOT the real domain.
     * e.g.  "paypal-secure.xyz" contains "paypal" but isn't paypal.com → flagged
     * e.g.  "paypal.com" contains "paypal" and IS paypal.com → NOT flagged
     */
    public static boolean isLookalikeOfTrustedBrand(String domain) {
        if (domain == null) return false;
        String lower = domain.toLowerCase();
        for (String brand : TRUSTED_BRANDS) {
            if (lower.contains(brand)) {
                // If it matches exactly the known real domain, it's fine
                // Known real domains list (simplified check)
                if (isKnownSafeDomain(lower)) return false;
                return true;  // contains brand name but isn't the real site
            }
        }
        return false;
    }

    /**
     * Counts the number of subdomains.
     * Legitimate sites rarely have more than 2 levels.
     * e.g.  "login.verify.paypal.secure.xyz" → 4 subdomains → suspicious
     */
    public static int countSubdomains(String domain) {
        if (domain == null) return 0;
        String[] parts = domain.split("\\.");
        return Math.max(0, parts.length - 2);
    }

    /**
     * Checks if URL has an IP address instead of a domain name.
     * e.g.  "http://192.168.1.1/login" — legitimate sites never do this.
     */
    public static boolean hasIpAddress(String rawUrl) {
        Pattern ipPattern = Pattern.compile(
                "https?://(\\d{1,3}\\.){3}\\d{1,3}"
        );
        return ipPattern.matcher(rawUrl).find();
    }

    /**
     * Checks if URL is excessively long (> 75 chars).
     * Phishing URLs are often very long to hide the real domain.
     */
    public static boolean isExcessivelyLong(String rawUrl) {
        return rawUrl != null && rawUrl.length() > 75;
    }

    /**
     * Extract all URLs from a block of text (used by SMS scanner).
     * Returns empty array if none found.
     */
    public static String[] extractUrlsFromText(String text) {
        if (text == null || text.isEmpty()) return new String[0];
        Matcher matcher = URL_PATTERN.matcher(text);
        java.util.List<String> found = new java.util.ArrayList<>();
        while (matcher.find()) {
            found.add(matcher.group());
        }
        return found.toArray(new String[0]);
    }

    // ═══════════════════════════════════════════════════════════════
    //  PRIVATE HELPERS
    // ═══════════════════════════════════════════════════════════════

    private static final List<String> KNOWN_SAFE_DOMAINS = Arrays.asList(
            "google.com", "www.google.com",
            "facebook.com", "www.facebook.com",
            "paypal.com", "www.paypal.com",
            "amazon.com", "www.amazon.com", "amazon.in",
            "apple.com", "www.apple.com",
            "microsoft.com", "www.microsoft.com",
            "sbi.co.in", "www.sbi.co.in", "onlinesbi.com",
            "hdfcbank.com", "www.hdfcbank.com",
            "icicibank.com", "www.icicibank.com",
            "paytm.com", "www.paytm.com",
            "phonepe.com", "www.phonepe.com"
    );

    private static boolean isKnownSafeDomain(String domain) {
        return KNOWN_SAFE_DOMAINS.contains(domain);
    }
}