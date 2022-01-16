package com.forgotten.fridatestapp;

import static com.forgotten.fridatestapp.HookedObject.getStringLength;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Toast;

import com.forgotten.fridatestapp.construct.ConstructoredObject;
import com.forgotten.fridatestapp.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding mBinding;
    private static final String TAG = "FridaTestApp";

    private HookedObject ho = new HookedObject();

    private ConstructoredObject co = new ConstructoredObject();


    static {
      System.loadLibrary("fridatestapp");
   }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        /** ViewBinding **/
        mBinding = ActivityMainBinding.inflate(getLayoutInflater());
        View view = mBinding.getRoot();
        setContentView(view);

        mBinding.btnMethodHooked.setOnClickListener(v -> {
            int addResult = ho.addNumber(3,6);
            Log.d(TAG, "btnMethodHooked: "+addResult);
            String hello = "helloFrida";
            hello = ho.stringTwo(hello);
            Log.d(TAG, "btnMethodHooked: "+hello);
            int sLen = getStringLength(hello);
            Log.d(TAG, "btnMethodHooked: "+sLen);
        });
        mBinding.btnParamConstructored.setOnClickListener(v-> co.main());

        mBinding.btnGetPassword.setOnClickListener(v->{
            String passwd = ho.getPasswd(mBinding.edtNameInput.getText().toString());
            Log.d("JNI", "dynamicString(): "+ dynamicString(mBinding.edtNameInput.getText().toString()));
            Log.d("JNI", "staticString(): "+ staticString(mBinding.edtNameInput.getText().toString()));
            Toast.makeText(getApplicationContext(), "passwd:"+passwd, Toast.LENGTH_SHORT).show();
        });

        mBinding.btnRunNative.setOnClickListener(v->{

            dynamicString("[My Input]");
        });
    }


    public native String dynamicString(String input);
    public native String staticString(String input);
}