package my.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @ClassName Base
 * @Description Base64自定义加解密示例
 * @Author Palmer
 * @Date 2022/2/3
 **/
public class Base {

    /**
     * Base64默认字符表
     */
    public static final String ORIGIN_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


    /**
     * Base64自定义加密
     *
     * @param data  待加密的字节数组
     * @param table 自定义字符表(len=65)
     * @return 自定义Base64加密后的字符串
     */
    public static String b64encodeSelf(byte[] data, String table) {
        if (table.length() != ORIGIN_TABLE.length()) {
            System.out.println("自定义字符表长度错误(len==65)");
            return null;
        }
        String endata = Base64.getEncoder().encodeToString(data);
        StringBuffer selfdata = new StringBuffer();
        // 用自定义表替换原始表
        for (int i = 0; i < endata.length(); i++) {
            int j = ORIGIN_TABLE.indexOf(endata.charAt(i));
            selfdata.append(table.charAt(j));
        }
        return new String(selfdata);
    }

    /**
     * Base64自定义解密
     *
     * @param data  待解密的字符串
     * @param table 自定义字符表(len=65)
     * @return 自定义Base64加解后的字符串
     */
    public static byte[] b64decodeSelf(String data, String table) {
        if (table.length() != ORIGIN_TABLE.length()) {
            return null;
        }
        StringBuffer selfdata = new StringBuffer();
        // 用原始表替换自定义表
        for (int i = 0; i < data.length(); i++) {
            int j = table.indexOf(data.charAt(i));
            selfdata.append(ORIGIN_TABLE.charAt(j));
        }
        return Base64.getDecoder().decode(new String(selfdata));
    }

    public static void main(String[] args) {
        String selfTable = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=";
        String enstr = b64encodeSelf("Forgo7ten".getBytes(StandardCharsets.UTF_8),selfTable);

        System.out.println(enstr);
        System.out.println(new String(b64decodeSelf(enstr,selfTable)));

    }
}