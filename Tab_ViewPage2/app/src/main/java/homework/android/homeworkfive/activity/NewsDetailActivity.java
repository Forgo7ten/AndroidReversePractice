package homework.android.homeworkfive.activity;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

import homework.android.homeworkfive.R;


public class NewsDetailActivity extends AppCompatActivity {

    private WebView webView;
    private String newsUrl;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_news_detail);
        initData();
        initViews();
    }

    private void initData() {
        Intent intent = getIntent();
        newsUrl = intent.getStringExtra("news_url");
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void initViews() {
        webView = findViewById(R.id.web_view);
        // 启用JS支持
        webView.getSettings().setJavaScriptEnabled(true);
        // 当需要从一个网页跳转到另一个网页时，我们希望目标网页仍然在当前WebView中显示，而不是打开系统浏览器
        webView.setWebViewClient(new WebViewClient());
        // 加载网页 也可以加载本地的html文件
        webView.loadUrl(newsUrl);
    }
}