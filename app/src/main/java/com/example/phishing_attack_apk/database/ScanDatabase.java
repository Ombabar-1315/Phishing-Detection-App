package com.example.phishing_attack_apk.database;

import android.content.Context;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

/**
 * ScanDatabase.java
 * The single Room database instance for the entire app.
 * Uses Singleton pattern — only one instance is ever created.
 *
 * Version: 1  (increment this if you change the schema later)
 */
@Database(entities = {ScanEntity.class}, version = 1, exportSchema = false)
public abstract class ScanDatabase extends RoomDatabase {

    public abstract ScanDao scanDao();

    // ── Singleton ────────────────────────────────────────────────────
    private static volatile ScanDatabase INSTANCE;

    public static ScanDatabase getInstance(Context context) {
        if (INSTANCE == null) {
            synchronized (ScanDatabase.class) {
                if (INSTANCE == null) {
                    INSTANCE = Room.databaseBuilder(
                                    context.getApplicationContext(),
                                    ScanDatabase.class,
                                    "phishing_detector_db"   // database file name
                            )
                            .fallbackToDestructiveMigration() // safe for student project
                            .build();
                }
            }
        }
        return INSTANCE;
    }
}