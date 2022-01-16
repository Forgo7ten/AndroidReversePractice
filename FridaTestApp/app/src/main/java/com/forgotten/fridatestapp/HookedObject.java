package com.forgotten.fridatestapp;

/**
 * @ClassName HookedObject
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/12/31
 **/
public class HookedObject {
    private static String msg = "你好";
    private int score;
    private static String stringTwo = "我与方法同名";

    public HookedObject() {
        score = 0;
    }

    public HookedObject(int score) {
        this.score = score;
    }

    public static String getMsg() {
        return msg;
    }

    public static void setMsg(String msg) {
        HookedObject.msg = msg;
    }

    /**
     * 获得字符串的长度；用作练习FridaHook
     *
     * @param hello
     * @return
     */
    public static int getStringLength(String hello) {
        return hello.length();
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    /**
     * 返回两倍的String；用作练习FridaHook
     *
     * @param hello
     * @return
     */
    public String stringTwo(String hello) {
        String temp = hello + hello;
        return temp;
    }

    /**
     * 两个数相加，返回其和；用作练习FridaHook
     *
     * @param x
     * @param y
     * @return
     */
    public int addNumber(int x, int y) {
        score += (x + y);
        return x + y;
    }

    /**
     * 两个数相加，返回其和；用作练习FridaHook(重载演示)
     *
     * @param x
     * @param y
     * @param z
     * @return
     */
    public double addNumber(int x, int y, int z) {
        score += (x + y + z);
        return x + y + z;
    }

    public String getPasswd(String name){
        char[] tmp = name.toCharArray();
        for(int i=0;i<tmp.length;++i){
            if(tmp[i]>='0'&&tmp[i]<='9'){
                tmp[i] =( char)('a' + tmp[i] - '0');
            }
        }
        return new String(tmp);
    }
}