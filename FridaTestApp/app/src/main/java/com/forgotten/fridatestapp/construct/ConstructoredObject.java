package com.forgotten.fridatestapp.construct;

import android.util.Log;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;




/**
 * @ClassName ConstructoredObject
 * @Description //TODO
 * @Author Palmer
 * @Date 2022/1/1
 **/
public class ConstructoredObject {
    enum Signal {
        GREEN, YELLOW, RED
    }
    private char arr[][] = new char[4][];
    private Map<String,String> map = new HashMap<>();
    private Signal color = Signal.RED;
    private Water wJuice = new Juice();

    public void testArray(){
        arr[0] = new char[] { '春' }; // 为每一行赋值
        arr[1] = new char[] { '处', '处' };
        arr[2] = new char[] { '夜', '来', '风' };
        arr[3] = new char[] { '花', '落', '知', '多'};

        for (int i = 0; i < 4; i++) { // 循环4行
            Log.d("testArray", Arrays.toString(arr[i]));
            Log.d("testArray", Arrays.toString (Arrays.toString (arr[i]).getBytes()));
            for (int j = 0; j < i+1; j++) { // 循环5列
                Log.d("testArray", Character.toString(arr[i][j])); // 输出数组中的元素
            }
            if (i % 2 == 0) {
                Log.d("testArray", ",");// 如果是一、三句，输出逗号
            } else {
                Log.d("testArray", "。");// 如果是二、四句，输出句号
            }
        }
    }

    public void testMap(){
        map.put("张三","20220101");
        map.put("李四","20220102");
        map.put("王五","20220103");
        map.put("赵六","20220104");
        Set<Map.Entry<String, String>> entries = map.entrySet();
        for (Map.Entry<String, String> entry : entries) {
            Log.d("testMap", "key:"+entry.getKey()+" value:"+entry.getValue());
        }

    }

    public void testEnum(){
        Log.d("testEnum", "color.name = "+color.name());
    }

    public void main(){
        testArray();
        testMap();
        testEnum();
        testTransform();
    }

    public void testTransform(){
        wJuice.still(wJuice);
        Juice juice = (Juice) wJuice;
        juice.fillEnergy();
    }


}