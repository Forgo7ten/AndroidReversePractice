package com.forgotten.firstjni;

/**
 * @ClassName Person
 * @Description //TODO
 * @Author yhnkkio
 * @Date 2021/12/1
 **/
public class Person {
    public static int sNumber;
    public static int[] testArray = {1, 2, 3, 4, 5};
    private static String country;

    static {
        sNumber = 100;
        country = "China";
    }

    public int mAge;
    private String mName;

    public Person(String mName) {
        this.mName = mName;
        this.mAge = 0;
    }

    public Person() {
        this.mName = "zhangsan";
        this.mAge = 999;
    }

    public Person(String mName, int mAge) {
        this.mName = mName;
        this.mAge = mAge;
    }

    public static int getsNumber() {
        return sNumber;
    }

    public static void setsNumber(int sNumber) {
        Person.sNumber = sNumber;
    }

    public static String getCountry() {
        return country;
    }

    public static void setCountry(String country) {
        Person.country = country;
    }

    private static int sMethod(String s) {
        return s.length();
    }

    public String getmName() {
        return mName;
    }

    public void setmName(String mName) {
        this.mName = mName;
    }

    public int getmAge() {
        return mAge;
    }

    public void setmAge(int mAge) {
        this.mAge = mAge;
    }

    private int mMethod(String s) {
        return s.length() + mName.length();
    }

    @Override
    public String toString() {
        return "Person{" +
                "mAge=" + mAge +
                ", mName='" + mName + '\'' +
                '}';
    }
}
