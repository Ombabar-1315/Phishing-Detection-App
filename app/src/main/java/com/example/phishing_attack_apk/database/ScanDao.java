package com.example.phishing_attack_apk.database;

import androidx.lifecycle.LiveData;
import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

/**
 * ScanDao.java
 * Data Access Object for scan_history table.
 * All database operations go through this interface.
 * Room auto-generates the implementation at compile time.
 */
@Dao
public interface ScanDao {

    // ── INSERT ───────────────────────────────────────────────────────

    /** Save a new scan to history. Ignores if duplicate id (safety). */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    void insertScan(ScanEntity scan);

    // ── SELECT ───────────────────────────────────────────────────────

    /** Get all scans, newest first. Returns LiveData so UI auto-updates. */
    @Query("SELECT * FROM scan_history ORDER BY timestamp DESC")
    LiveData<List<ScanEntity>> getAllScans();

    /** Get only PHISHING results for report screen */
    @Query("SELECT * FROM scan_history WHERE risk_level = 'PHISHING' ORDER BY timestamp DESC")
    LiveData<List<ScanEntity>> getPhishingScans();

    /** Get total number of scans ever done */
    @Query("SELECT COUNT(*) FROM scan_history")
    int getTotalScanCount();

    /** Get count of phishing detections */
    @Query("SELECT COUNT(*) FROM scan_history WHERE risk_level = 'PHISHING'")
    int getPhishingCount();

    // ── DELETE ───────────────────────────────────────────────────────

    /** Clear all history — for settings screen "clear history" button */
    @Query("DELETE FROM scan_history")
    void clearAllHistory();

    /** Delete one specific entry by id */
    @Query("DELETE FROM scan_history WHERE id = :scanId")
    void deleteScanById(int scanId);
}