package com.forgotten.firstjni;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.forgotten.firstjni.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'firstjni' library on application startup.
    static {
        System.loadLibrary("firstjni");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(stringFromJNI());
        useObjectStaticField();
        useObjectField1();
        useObjectField2();
        useArray();
        for (int i = 0; i < 5; ++i) {
            Log.d("useArray", "array[" + i + "]=" + Person.testArray[i]);
        }
        openNativeActivity();
        useMethod();
        testLGRef();
    }

    private native void testLGRef();

    public native void useMethod();

    private void openNativeActivity() {
        Button openBtn = findViewById(R.id.open_btn);
        openBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setClass(getApplicationContext(), NativeActivity.class);
                startActivity(intent);
            }
        });
    }

    /**
     * A native method that is implemented by the 'firstjni' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native String stringFromHello();

    public native void useObjectStaticField();

    public native void useObjectField1();

    public native void useObjectField2();

    public native void useArray();
}