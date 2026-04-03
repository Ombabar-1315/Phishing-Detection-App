package com.example.phishing_attack_apk.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.phishing_attack_apk.R;
import com.example.phishing_attack_apk.database.ScanDatabase;
import com.example.phishing_attack_apk.database.ScanEntity;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * HistoryActivity.java
 * Shows all past scans from the Room database using a RecyclerView.
 * LiveData auto-updates the list whenever a new scan is saved.
 */
public class HistoryActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private HistoryAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_history);

        recyclerView = findViewById(R.id.rv_history);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        adapter = new HistoryAdapter();
        recyclerView.setAdapter(adapter);

        // LiveData observer — list updates automatically when new scan saved
        ScanDatabase.getInstance(this)
                .scanDao()
                .getAllScans()
                .observe(this, scans -> {
                    adapter.setScans(scans);
                    // Show empty state if no scans yet
                    TextView tvEmpty = findViewById(R.id.tv_empty);
                    if (tvEmpty != null) {
                        tvEmpty.setVisibility(
                                scans == null || scans.isEmpty()
                                        ? View.VISIBLE : View.GONE);
                    }
                });
    }

    // ══════════════════════════════════════════════════════════════
    //  RecyclerView Adapter
    // ══════════════════════════════════════════════════════════════
    static class HistoryAdapter extends RecyclerView.Adapter<HistoryAdapter.ViewHolder> {

        private List<ScanEntity> scans;

        void setScans(List<ScanEntity> scans) {
            this.scans = scans;
            notifyDataSetChanged();
        }

        @Override
        public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_history, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(ViewHolder holder, int position) {
            ScanEntity scan = scans.get(position);

            // Trim URL for display
            String displayUrl = scan.url != null && scan.url.length() > 45
                    ? scan.url.substring(0, 45) + "..."
                    : scan.url;

            holder.tvUrl.setText(displayUrl);
            holder.tvLevel.setText(scan.riskLevel);
            holder.tvScore.setText(scan.riskScore + "/100");
            holder.tvSource.setText(scan.sourceType);

            // Format timestamp
            String date = new SimpleDateFormat(
                    "dd MMM yyyy, hh:mm a", Locale.getDefault())
                    .format(new Date(scan.timestamp));
            holder.tvDate.setText(date);

            // Color the level badge
            int color;
            switch (scan.riskLevel != null ? scan.riskLevel : "") {
                case "SAFE":       color = 0xFF2E7D32; break; // dark green
                case "SUSPICIOUS": color = 0xFFF57F17; break; // amber
                default:           color = 0xFFC62828; break; // dark red
            }
            holder.tvLevel.setTextColor(color);
        }

        @Override
        public int getItemCount() {
            return scans == null ? 0 : scans.size();
        }

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvUrl, tvLevel, tvScore, tvSource, tvDate;

            ViewHolder(View view) {
                super(view);
                tvUrl    = view.findViewById(R.id.tv_history_url);
                tvLevel  = view.findViewById(R.id.tv_history_level);
                tvScore  = view.findViewById(R.id.tv_history_score);
                tvSource = view.findViewById(R.id.tv_history_source);
                tvDate   = view.findViewById(R.id.tv_history_date);
            }
        }
    }
}