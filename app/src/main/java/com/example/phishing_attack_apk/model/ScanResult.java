package com.example.phishing_attack_apk.model;

import java.util.ArrayList;
import java.util.List;

/**
 * ScanResult.java
 * Core data model — holds the complete result of one URL scan.
 * Created by SecurityEngine, displayed in ResultActivity,
 * and saved to Room database via ScanEntity.
 */
public class ScanResult {

    // Risk level constants — use these everywhere, never raw strings
    public static final String LEVEL_SAFE       = "SAFE";
    public static final String LEVEL_SUSPICIOUS = "SUSPICIOUS";
    public static final String LEVEL_PHISHING   = "PHISHING";

    // Source type constants
    public static final String SOURCE_MANUAL = "MANUAL";
    public static final String SOURCE_QR     = "QR";
    public static final String SOURCE_SMS    = "SMS";

    private String       url;
    private int          riskScore;    // 0–100
    private String       riskLevel;    // SAFE / SUSPICIOUS / PHISHING
    private List<String> reasons;      // why each point was added
    private long         timestamp;
    private String       sourceType;   // how URL entered the app

    // ── Constructor ──────────────────────────────────────────────────
    public ScanResult(String url, String sourceType) {
        this.url        = url;
        this.sourceType = sourceType;
        this.riskScore  = 0;
        this.reasons    = new ArrayList<>();
        this.timestamp  = System.currentTimeMillis();
    }

    // ── Business logic ───────────────────────────────────────────────

    /** Add one reason string — called by SecurityEngine per failed check */
    public void addReason(String reason) {
        reasons.add(reason);
    }

    /** Add points to the risk score */
    public void addScore(int points) {
        this.riskScore += points;
        // Cap at 100
        if (this.riskScore > 100) this.riskScore = 100;
    }

    /**
     * Must be called AFTER all checks are done.
     * Converts the numeric score to a label.
     *   0–30  → SAFE
     *  31–60  → SUSPICIOUS
     *  61–100 → PHISHING
     */
    public void computeRiskLevel() {
        if (riskScore <= 30) {
            riskLevel = LEVEL_SAFE;
        } else if (riskScore <= 60) {
            riskLevel = LEVEL_SUSPICIOUS;
        } else {
            riskLevel = LEVEL_PHISHING;
        }
    }

    public boolean isPhishing()    { return LEVEL_PHISHING.equals(riskLevel); }
    public boolean isSuspicious()  { return LEVEL_SUSPICIOUS.equals(riskLevel); }
    public boolean isSafe()        { return LEVEL_SAFE.equals(riskLevel); }

    // ── Getters & Setters ────────────────────────────────────────────
    public String       getUrl()        { return url; }
    public int          getRiskScore()  { return riskScore; }
    public String       getRiskLevel()  { return riskLevel; }
    public List<String> getReasons()    { return reasons; }
    public long         getTimestamp()  { return timestamp; }
    public String       getSourceType() { return sourceType; }

    public void setRiskScore(int score)    { this.riskScore = score; }
    public void setRiskLevel(String level) { this.riskLevel = level; }
}