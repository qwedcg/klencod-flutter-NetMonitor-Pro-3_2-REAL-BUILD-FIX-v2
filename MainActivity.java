package com.netmonitor.pro;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class MainActivity extends Activity {
    private static final int VPN_REQUEST = 100;
    private static final int CREATE_FILE = 200;
    private static final String PREFS = "netmonitor";
    private static final String KEY_APPS = "apps";
    private static final String KEY_MIN = "minPort";
    private static final String KEY_MAX = "maxPort";
    private static final String KEY_GAME_ONLY = "gameOnly";

    private TextView status, stats, game, log, selectedInfo;
    private SharedPreferences prefs;
    private int exportType;
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshTask = new Runnable() {
        @Override public void run() {
            refresh();
            refreshSelectedInfo();
            refreshHandler.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        status = findViewById(R.id.status);
        stats = findViewById(R.id.stats);
        game = findViewById(R.id.game);
        log = findViewById(R.id.log);
        selectedInfo = findViewById(R.id.selectedInfo);

        findViewById(R.id.startButton).setOnClickListener(v -> requestVpn());
        findViewById(R.id.stopButton).setOnClickListener(v -> stopMonitoring());
        findViewById(R.id.appsButton).setOnClickListener(v -> showAppsDialog());
        findViewById(R.id.settingsButton).setOnClickListener(v -> showSettings());
        findViewById(R.id.csvButton).setOnClickListener(v -> beginExport(false));
        findViewById(R.id.jsonButton).setOnClickListener(v -> beginExport(true));
        findViewById(R.id.clearButton).setOnClickListener(v -> { MonitorVpnService.clearRecords(); refresh(); });
        findViewById(R.id.shareButton).setOnClickListener(v -> shareText());
        findViewById(R.id.helpButton).setOnClickListener(v -> showHelp());

        refreshSelectedInfo();
        refresh();
    }

    @Override protected void onResume() {
        super.onResume();
        refreshSelectedInfo();
        refresh();
        refreshHandler.removeCallbacks(refreshTask);
        refreshHandler.post(refreshTask);
    }

    @Override protected void onPause() {
        refreshHandler.removeCallbacks(refreshTask);
        super.onPause();
    }

    private void requestVpn() {
        if (getSelectedPackages().isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("اختيار التطبيقات")
                    .setMessage("لم تحدد تطبيقات. هل تريد مراقبة كل التطبيقات؟")
                    .setNegativeButton("اختيار", (d, w) -> showAppsDialog())
                    .setPositiveButton("كل التطبيقات", (d, w) -> prepareVpn())
                    .show();
        } else prepareVpn();
    }

    private void prepareVpn() {
        Intent intent = VpnService.prepare(this);
        if (intent != null) startActivityForResult(intent, VPN_REQUEST);
        else startMonitoring();
    }

    private void startMonitoring() {
        Intent i = new Intent(this, MonitorVpnService.class);
        i.setAction(MonitorVpnService.ACTION_START);
        if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
        status.setText("● جاري المراقبة");
        status.setTextColor(0xFF49E28C);
    }

    private void stopMonitoring() {
        stopService(new Intent(this, MonitorVpnService.class));
        status.setText("● متوقف");
        status.setTextColor(0xFFFF5C72);
    }

    private Set<String> getSelectedPackages() {
        Set<String> set = new HashSet<>();
        String raw = prefs.getString(KEY_APPS, "");
        if (!raw.isEmpty()) Collections.addAll(set, raw.split("\\|"));
        return set;
    }

    private void showAppsDialog() {
        PackageManager pm = getPackageManager();
        List<ApplicationInfo> apps = new ArrayList<>();
        for (ApplicationInfo ai : pm.getInstalledApplications(PackageManager.GET_META_DATA)) {
            if (ai.packageName.equals(getPackageName())) continue;
            boolean launchable = pm.getLaunchIntentForPackage(ai.packageName) != null;
            boolean userApp = (ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0;
            boolean updatedSystem = (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
            if (launchable && (userApp || updatedSystem)) apps.add(ai);
        }
        // Some Android vendor launchers hide package metadata. If the normal
        // launcher filter returns nothing, show every non-system package as a
        // safe fallback so the picker cannot appear empty.
        if (apps.isEmpty()) {
            for (ApplicationInfo ai : pm.getInstalledApplications(PackageManager.GET_META_DATA)) {
                if (ai.packageName.equals(getPackageName())) continue;
                boolean userApp = (ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0;
                boolean updatedSystem = (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
                if (userApp || updatedSystem) apps.add(ai);
            }
        }
        apps.sort(Comparator.comparing(ai -> String.valueOf(pm.getApplicationLabel(ai)).toLowerCase()));
        String[] labels = new String[apps.size()];
        boolean[] checked = new boolean[apps.size()];
        Set<String> selected = getSelectedPackages();
        for (int i = 0; i < apps.size(); i++) {
            labels[i] = String.valueOf(pm.getApplicationLabel(apps.get(i)));
            checked[i] = selected.contains(apps.get(i).packageName);
        }
        if (apps.isEmpty()) {
            Toast.makeText(this, "لم يتم العثور على تطبيقات قابلة للتشغيل. تأكد من إصدار التطبيق الجديد وصلاحيات حزم التطبيقات.", Toast.LENGTH_LONG).show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("تحديد التطبيقات للمراقبة")
                .setMultiChoiceItems(labels, checked, (d, which, isChecked) -> checked[which] = isChecked)
                .setNeutralButton("كل التطبيقات", (d, w) -> {
                    prefs.edit().putString(KEY_APPS, "").apply(); refreshSelectedInfo();
                })
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("حفظ", (d, w) -> {
                    StringBuilder s = new StringBuilder();
                    for (int i = 0; i < apps.size(); i++) if (checked[i]) {
                        if (s.length() > 0) s.append('|');
                        s.append(apps.get(i).packageName);
                    }
                    prefs.edit().putString(KEY_APPS, s.toString()).apply();
                    refreshSelectedInfo();
                }).show();
    }

    private void showSettings() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(40, 10, 40, 0);
        EditText min = new EditText(this); min.setHint("الحد الأدنى للمنفذ"); min.setInputType(2);
        EditText max = new EditText(this); max.setHint("الحد الأقصى للمنفذ"); max.setInputType(2);
        min.setText(String.valueOf(prefs.getInt(KEY_MIN, 1)));
        max.setText(String.valueOf(prefs.getInt(KEY_MAX, 65535)));
        CheckBox gameOnly = new CheckBox(this);
        gameOnly.setText("إظهار اتصالات الألعاب فقط");
        gameOnly.setChecked(prefs.getBoolean(KEY_GAME_ONLY, false));
        box.addView(min); box.addView(max); box.addView(gameOnly);
        new AlertDialog.Builder(this).setTitle("الإعدادات").setView(box)
                .setNegativeButton("إلغاء", null)
                .setPositiveButton("تطبيق", (d, w) -> {
                    try {
                        int a = Math.max(1, Math.min(65535, Integer.parseInt(min.getText().toString())));
                        int z = Math.max(a, Math.min(65535, Integer.parseInt(max.getText().toString())));
                        prefs.edit().putInt(KEY_MIN, a).putInt(KEY_MAX, z).putBoolean(KEY_GAME_ONLY, gameOnly.isChecked()).apply();
                    } catch (Exception e) { Toast.makeText(this, "أدخل أرقاماً صحيحة", Toast.LENGTH_SHORT).show(); }
                }).show();
    }

    private void refreshSelectedInfo() {
        Set<String> apps = getSelectedPackages();
        selectedInfo.setText(apps.isEmpty() ? "المصدر: كل التطبيقات" : "المصدر: " + apps.size() + " تطبيق محدد");
    }

    private void refresh() {
        MonitorVpnService.Stats s = MonitorVpnService.getStats();
        stats.setText("🌐 IPs: " + s.ips + "    🔌 Ports: " + s.ports + "    📦 Packets: " + s.packets);
        game.setText("🎮 " + (s.game.isEmpty() ? "لم يتم اكتشاف لعبة" : "تم اكتشاف: " + s.game));
        log.setText(s.log.isEmpty() ? (s.error.isEmpty() ? "لا توجد اتصالات بعد.\nشغّل المراقبة ثم افتح التطبيق المحدد." : "خطأ: " + s.error) : s.log);
        if (MonitorVpnService.isRunning()) {
            status.setText("● جاري المراقبة"); status.setTextColor(0xFF49E28C);
        } else if (!s.error.isEmpty()) {
            status.setText("● فشل بدء المراقبة"); status.setTextColor(0xFFFF5C72);
        }
    }

    private void beginExport(boolean json) {
        exportType = json ? 2 : 1;
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        i.setType(json ? "application/json" : "text/csv");
        i.putExtra(Intent.EXTRA_TITLE, json ? "netmonitor.json" : "netmonitor.csv");
        startActivityForResult(i, CREATE_FILE);
    }

    private void shareText() {
        Intent i = new Intent(Intent.ACTION_SEND);
        i.setType("text/plain");
        i.putExtra(Intent.EXTRA_TEXT, MonitorVpnService.getStats().log);
        startActivity(Intent.createChooser(i, "مشاركة الاتصالات"));
    }

    private void showHelp() {
        new AlertDialog.Builder(this).setTitle("NetMonitor Pro")
                .setMessage("اختر التطبيقات، ثم وافق على VPN وابدأ المراقبة.\n\nهذه النسخة تستخدم VpnService مع محرك tun2socks حقيقي لتمرير TCP وUDP إلى الإنترنت. يتم تسجيل عنوان الوجهة والمنفذ عند إنشاء تدفق TCP وعند إرسال تدفق UDP، ثم تظهر النتائج مباشرة في القائمة.\n\nعند اختيار تطبيقات محددة، تكون تلك التطبيقات هي التي تمر عبر المراقبة فقط. إذا اخترت أكثر من تطبيق، يظهر المصدر كعدد التطبيقات المحددة لأن Android لا يعطي هوية التطبيق داخل كل حزمة عبر TUN بشكل مباشر.")
                .setPositiveButton("حسناً", null).show();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) startMonitoring();
        if (requestCode == CREATE_FILE && resultCode == RESULT_OK && data != null && data.getData() != null) {
            try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
                String content = exportType == 2 ? MonitorVpnService.exportJson() : MonitorVpnService.exportCsv();
                out.write(content.getBytes(StandardCharsets.UTF_8));
                Toast.makeText(this, "تم التصدير", Toast.LENGTH_SHORT).show();
            } catch (Exception e) { Toast.makeText(this, "فشل التصدير", Toast.LENGTH_LONG).show(); }
        }
    }
}
