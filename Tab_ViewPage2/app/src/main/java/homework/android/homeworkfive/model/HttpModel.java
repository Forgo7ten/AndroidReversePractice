package homework.android.homeworkfive.model;

import android.os.Handler;
import android.os.Message;
import android.util.Log;

import androidx.annotation.NonNull;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import homework.android.homeworkfive.entity.News;
import homework.android.homeworkfive.entity.Param;
import homework.android.homeworkfive.util.HttpUtil;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Response;

public class HttpModel {
    public static final int GET_LIST_CODE = 100;
    public static final int REFRESH_LIST = 200;
    public static final int LODE_MORE = 300;
    private static final String TAG = "Five-HttpModel";

    public void getNewsList(Param param, Handler handler, int code) {
        HashMap<String, String> paramMap = new HashMap<String, String>() {
            {
                put("key", Param.getKey());
                put("type", param.getType());
                put("page", String.valueOf(param.getPage()));
                put("page_size", String.valueOf(param.getPage_size()));
                put("is_filter", String.valueOf(param.getIs_filter()));
            }
        };
        HttpUtil.sendPostRequest(paramMap, new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                e.printStackTrace();
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                String result = Objects.requireNonNull(response.body()).string();
                Log.d(TAG, "onResponse: " + result);
                List<News> newsList = resToNews(result);
                Message message = new Message();
                message.what = code;
                message.obj = newsList;
                handler.sendMessage(message);
            }
        });
    }

    public List<News> resToNews(String res) {
        List<News> newsList = new ArrayList<>();
        Gson gson = new Gson();
        JsonObject root = new JsonParser().parse(res).getAsJsonObject();
        if ("0".equals(root.get("error_code").getAsString())) {
            JsonArray data = root.get("result").getAsJsonObject().get("data").getAsJsonArray();
            newsList = gson.fromJson(data, new TypeToken<List<News>>() {
            }.getType());
        }
        return newsList;
    }
}
