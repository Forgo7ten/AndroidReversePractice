package homework.android.homeworkfive.util;

import java.util.Map;
import java.util.Set;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;

public class HttpUtil {
    public static final String BASE_URL = "http://v.juhe.cn/toutiao/index";
    public static OkHttpClient client;

    static {
        client = new OkHttpClient.Builder()
                .build();
    }

    public static void sendPostRequest(Map<String, String> paramMap, Callback callback) {
        FormBody.Builder builder = new FormBody.Builder();
        Set<String> keys = paramMap.keySet();
        for (String key : keys) {
            String value = paramMap.get(key);
            builder.add(key, value);
        }
        FormBody form = builder.build();
        Request request = new Request.Builder()
                .url(BASE_URL)
                .post(form)
                .build();
        Call call = client.newCall(request);
        call.enqueue(callback);
    }
}
