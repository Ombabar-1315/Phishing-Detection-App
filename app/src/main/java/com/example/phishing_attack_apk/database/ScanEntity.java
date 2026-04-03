package com.example.phishing_attack_apk.database;

import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.PrimaryKey;

/**
 * ScanEntity.java
 * Room database table definition.
 * Each row = one completed scan stored in history.
 *
 * Table name: scan_history
 */
@Entity(tableName = "scan_history")
public class ScanEntity {

    @PrimaryKey(autoGenerate = true)
    public int id;

    @ColumnInfo(name = "url")
    public String url;

    @ColumnInfo(name = "risk_score")
    public int riskScore;

    @ColumnInfo(name = "risk_level")
    public String riskLevel;          // SAFE / SUSPICIOUS / PHISHING

    @ColumnInfo(name = "reasons")
    public String reasons;            // stored as comma-separated string

    @ColumnInfo(name = "source_type")
    public String sourceType;         // MANUAL / QR / SMS

    @ColumnInfo(name = "timestamp")
    public long timestamp;

    // ── Constructor ──────────────────────────────────────────────────
    public ScanEntity(String url, int riskScore, String riskLevel,
                      String reasons, String sourceType, long timestamp) {
        this.url        = url;
        this.riskScore  = riskScore;
        this.riskLevel  = riskLevel;
        this.reasons    = reasons;
        this.sourceType = sourceType;
        this.timestamp  = timestamp;
    }

    /**
     * Helper: build a ScanEntity directly from a ScanResult object.
     * Reasons list is joined with " | " for clean display in history.
     */
    public static ScanEntity fromScanResult(
            com.example.phishing_attack_apk.model.ScanResult result) {

        String reasonsStr = android.text.TextUtils.join(" | ", result.getReasons());

        return new ScanEntity(
                result.getUrl(),
                result.getRiskScore(),
                result.getRiskLevel(),
                reasonsStr,
                result.getSourceType(),
                result.getTimestamp()
        );
    }
}