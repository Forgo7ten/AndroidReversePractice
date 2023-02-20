package homework.android.homeworkfive.entity;

import java.util.HashMap;
import java.util.Map;

public class Param {
    private static final Map<String, String> tabMap = new HashMap<String, String>() {
        {
            put("推荐", "top");
            put("国内", "guonei");
            put("国际", "guoji");
            put("娱乐", "yule");
            put("体育", "tiyu");
            put("军事", "junshi");
            put("科技", "keji");
            put("财经", "caijing");
            put("时尚", "shishang");
            put("游戏", "youxi");
            put("汽车", "qiche");
            put("健康", "jiankang");
        }
    };
    private static final String key = "75c48e73e76ac4307aedf04eadb0cbbf";
    private int page;
    private int page_size;
    private int is_filter;
    private String type;

    public Param(int page, int page_size, int is_filter, String type) {
        this.page = page;
        this.page_size = page_size;
        this.is_filter = is_filter;
        this.type = tabMap.get(type);
    }

    public Param(String type) {
        this.page = 1;
        this.page_size = 10;
        this.is_filter = 1;
        this.type = tabMap.get(type);
    }

    public Param() {
    }

    public static String getKey() {
        return key;
    }

    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public Param addPage() {
        this.page += 1;
        return this;
    }

    public Param addPage(int num) {
        this.page += num;
        return this;
    }

    public int getPage_size() {
        return page_size;
    }

    public void setPage_size(int page_size) {
        this.page_size = page_size;
    }

    public int getIs_filter() {
        return is_filter;
    }

    public void setIs_filter(int is_filter) {
        this.is_filter = is_filter;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }
}
