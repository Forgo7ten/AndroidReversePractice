package com.forgotten.actlyloadcomptestapp;

import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class TestOneActivity extends AppCompatActivity {
    private static final String TAG = "ActlyLoadComp";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test_one);
        Log.d(TAG, "onCreate: TestOneActivity");
        Toast.makeText(getApplicationContext(), "TestOneActivity", Toast.LENGTH_SHORT).show();

    }
}