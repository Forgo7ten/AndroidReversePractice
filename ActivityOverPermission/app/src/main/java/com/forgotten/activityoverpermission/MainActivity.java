package com.forgotten.activityoverpermission;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private EditText usernameEdt;
    private EditText passwordEdt;
    private Button loginBut;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initViews();
        setListeners();
    }

    private void setListeners() {
        MyOnClickListener listener = new MyOnClickListener();
        loginBut.setOnClickListener(listener);
    }

    private void login() {
        String username = usernameEdt.getText().toString();
        String password = passwordEdt.getText().toString();
        // 验证账号是否为admin，密码是否为123456
        if ("admin".equals(username) && "123456".equals(password)) {
            Toast.makeText(getApplicationContext(), "Success!", Toast.LENGTH_SHORT).show();
            // 验证成功则跳转到SuccessActivity
            Intent intent = new Intent(MainActivity.this, SuccessActivity.class);
            startActivity(intent);
        } else {
            Toast.makeText(getApplicationContext(), "Failed.", Toast.LENGTH_SHORT).show();
        }
    }

    private void initViews() {
        usernameEdt = findViewById(R.id.username);
        passwordEdt = findViewById(R.id.password);
        loginBut = findViewById(R.id.login);
    }

    class MyOnClickListener implements View.OnClickListener {
        @Override
        public void onClick(View v) {
            switch (v.getId()) {
                case R.id.login:
                    login();
                    break;
            }
        }
    }
}