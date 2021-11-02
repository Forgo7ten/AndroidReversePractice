package com.forgotten.activityhijacking;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

public class HijackPage extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hijack_page);
    }
}