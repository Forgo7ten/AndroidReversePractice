package homework.android.homeworkfive;

import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import homework.android.homeworkfive.adapter.TabAdapter;
import homework.android.homeworkfive.model.HttpModel;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "Five-Main";
    private final List<String> tabList = new ArrayList<>(Arrays.asList("推荐", "国内", "国际", "娱乐", "体育", "军事", "科技", "财经", "时尚", "游戏", "汽车", "健康"));
    private TabLayout tabLayout;
    private ViewPager2 pager;
    private TabAdapter tabAdapter;
    private HttpModel httpModel;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initViews();
        initPager();
    }

    private void initPager() {
        tabAdapter = new TabAdapter(getSupportFragmentManager(), getLifecycle(), tabList);
        pager.setAdapter(tabAdapter);
        TabLayoutMediator mediator = new TabLayoutMediator(tabLayout, pager, new TabLayoutMediator.TabConfigurationStrategy() {
            @Override
            public void onConfigureTab(@NonNull TabLayout.Tab tab, int position) {
                tab.setText(tabList.get(position));
            }
        });
        mediator.attach();
        pager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                super.onPageScrolled(position, positionOffset, positionOffsetPixels);
            }

            @Override
            public void onPageScrollStateChanged(int state) {
                super.onPageScrollStateChanged(state);
            }

            @Override
            public void onPageSelected(int position) {
                super.onPageSelected(position);
                Log.d(TAG, "onPageSelected: " + position);
            }
        });
    }

    private void initViews() {
        tabLayout = findViewById(R.id.tab_layout);
        pager = findViewById(R.id.pager);
    }
}