package com.forgotten.firstjni;

import android.os.Bundle;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;

public class NativeActivity extends AppCompatActivity {

    static {
        System.loadLibrary("nactivity");
    }

    protected native void onCreate(Bundle savedInstanceState);

    // @Override
    // protected void onCreate(Bundle savedInstanceState) {
    //     super.onCreate(savedInstanceState);
    //     setContentView(R.layout.activity_native);
    // }

    private void javaOnCreate() {
        int dynamicLen = dynamicGetLen("dynamicGetLen");
        Log.d("javaOnCreate", "dynamic_len= " + dynamicLen);
        dynamicPrintNum(5);
    }

    private native int dynamicGetLen(String str);

    private native void dynamicPrintNum(int num);
}