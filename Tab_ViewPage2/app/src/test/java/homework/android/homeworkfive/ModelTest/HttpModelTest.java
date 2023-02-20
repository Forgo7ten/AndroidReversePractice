package homework.android.homeworkfive.ModelTest;

import org.junit.Test;

import java.util.List;

import homework.android.homeworkfive.entity.News;
import homework.android.homeworkfive.model.HttpModel;

public class HttpModelTest {
    @Test
    public void resToNewsTest() {
        String res = "{\n" +
                "    \"reason\": \"success\",\n" +
                "    \"result\": {\n" +
                "        \"stat\": \"1\",\n" +
                "        \"data\": [\n" +
                "            {\n" +
                "                \"uniquekey\": \"db61b977d9fabd0429c6d0c671aeb30e\",\n" +
                "                \"title\": \"“新时代女性的自我关爱”主题沙龙暨双山街道福泰社区妇儿活动家园启动仪式举行\",\n" +
                "                \"date\": \"2021-03-08 13:47:00\",\n" +
                "                \"category\": \"头条\",\n" +
                "                \"author_name\": \"鲁网\",\n" +
                "                \"url\": \"https://mini.eastday.com/mobile/210308134708834241845.html\",\n" +
                "                \"thumbnail_pic_s\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308134708_d0216565f1d6fe1abdfa03efb4f3e23c_0_mwpm_03201609.png\",\n" +
                "                \"thumbnail_pic_s02\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308134708_d0216565f1d6fe1abdfa03efb4f3e23c_1_mwpm_03201609.png\",\n" +
                "                \"thumbnail_pic_s03\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308134708_d0216565f1d6fe1abdfa03efb4f3e23c_2_mwpm_03201609.png\",\n" +
                "                \"is_content\": \"1\"\n" +
                "            },\n" +
                "            {\n" +
                "                \"uniquekey\": \"7d246cbfa9000fb5ac42fb3bb934a592\",\n" +
                "                \"title\": \"滴滴发布女司机数据：2020年新增女性网约车司机超26万\",\n" +
                "                \"date\": \"2021-03-08 13:40:00\",\n" +
                "                \"category\": \"头条\",\n" +
                "                \"author_name\": \"国青年网\",\n" +
                "                \"url\": \"https://mini.eastday.com/mobile/210308134023641877777.html\",\n" +
                "                \"thumbnail_pic_s\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308134023_7a9ca0543b00332147c42e1ee4146908_0_mwpm_03201609.png\",\n" +
                "                \"thumbnail_pic_s02\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308134023_7a9ca0543b00332147c42e1ee4146908_1_mwpm_03201609.jpeg\",\n" +
                "                \"is_content\": \"1\"\n" +
                "            },\n" +
                "            {\n" +
                "                \"uniquekey\": \"c0611bea6eb961a57b21a0d1008bbe2e\",\n" +
                "                \"title\": \"点赞！东海县公安局学雷锋见行动\",\n" +
                "                \"date\": \"2021-03-08 13:38:00\",\n" +
                "                \"category\": \"头条\",\n" +
                "                \"author_name\": \"江南时报\",\n" +
                "                \"url\": \"https://mini.eastday.com/mobile/210308133849892734209.html\",\n" +
                "                \"thumbnail_pic_s\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308133849_b9f3d069a1ab400bf2d87fcc15793ca5_1_mwpm_03201609.png\",\n" +
                "                \"thumbnail_pic_s02\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308133849_b9f3d069a1ab400bf2d87fcc15793ca5_2_mwpm_03201609.png\",\n" +
                "                \"thumbnail_pic_s03\": \"https://dfzximg02.dftoutiao.com/news/20210308/20210308133849_b9f3d069a1ab400bf2d87fcc15793ca5_3_mwpm_03201609.png\",\n" +
                "                \"is_content\": \"1\"\n" +
                "            }\n" +
                "        ],\n" +
                "        \"page\": \"1\",\n" +
                "        \"pageSize\": \"3\"\n" +
                "    },\n" +
                "    \"error_code\": 0\n" +
                "}";
        HttpModel httpModel = new HttpModel();
        List<News> newsList = httpModel.resToNews(res);
        newsList.stream().forEach(System.out::println);
    }
}
