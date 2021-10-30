package com.forgotten.actlyloadcomptestapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

public class TestTwoActivity extends Activity {
    private static final String TAG = "ActlyLoadComp";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_two);
        Log.d(TAG, "onCreate: TestTwoActivity");
        Toast.makeText(getApplicationContext(), "TestTwoActivity", Toast.LENGTH_SHORT).show();

    }
}