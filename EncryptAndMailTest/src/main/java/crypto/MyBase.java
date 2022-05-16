package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Security;

/**
 * @ClassName MyBase
 * @Description base系列算法
 * @Author Palmer
 * @Date 2021/7/12
 **/
public class MyBase {
    /**
     * 字符编码
     */
    public static final Charset UTF8 = StandardCharsets.UTF_8;

    /**
     * Base64默认字符表
     */
    public static final String ORIGIN_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    static {
        // 引用BC工具类
        Security.addProvider(new BouncyCastleProvider());
    }


    private MyBase() {
    }

    /**
     * base64加密方法
     *
     * @param data 待加密的字符串
     * @return 加密后的字符串
     */
    public static String b64encodeToStr(String data) {
        return b64encodeToStr(data.getBytes(UTF8));
    }

    /**
     * base64加密方法
     *
     * @param data 待加密的字符数组
     * @return 加密后的字符串
     */
    public static String b64encodeToStr(byte[] data) {
        // 将字节数组加密成base64编码的字节数组
        byte[] enbyte = Base64.encode(data);
        return new String(enbyte, UTF8);
    }

    /**
     * base64加密方法
     *
     * @param data 待加密的字符数组
     * @return 加密后的字符数组
     */
    public static byte[] b64encodeToByte(byte[] data) {
        // 将字节数组加密成base64编码的字节数组
        byte[] enbyte = Base64.encode(data);
        return enbyte;
    }


    /**
     * base64解密方法
     *
     * @param endata 待解密的字符数组
     * @return 解密后的字符数组
     */
    public static byte[] b64decodeToByte(byte[] endata) {
        byte[] decode = Base64.decode(endata);
        return decode;
    }

    /**
     * base64解密方法
     *
     * @param endata 待解密的字符串
     * @return 解密后的字符数组
     */
    public static byte[] b64decodeToByte(String endata) {
        byte[] decode = Base64.decode(endata);
        return decode;
    }

    /**
     * base64解密方法
     *
     * @param endata 待解密的字符数组
     * @return 解密后的字符串
     */
    public static String b64decodeToStr(byte[] endata) {
        byte[] decode = Base64.decode(endata);
        return new String(decode, UTF8);
    }

    /**
     * base64解密方法
     *
     * @param endata 待解密的字符串
     * @return 解密后的字符串
     */
    public static String b64decodeToStr(String endata) {
        byte[] decode = Base64.decode(endata);
        return new String(decode, UTF8);
    }


    /**
     * Base64自定义加密
     *
     * @param data  待加密的字符串
     * @param table 自定义字符表(len=65)
     * @return 自定义Base64加密后的字符串
     */
    public static String b64encodeSelf(String data, String table) {
        if (table.length() != ORIGIN_TABLE.length()) {
            return null;
        }
        String endata = b64encodeToStr(data);
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
    public static String b64decodeSelf(String data, String table) {
        if (table.length() != ORIGIN_TABLE.length()) {
            return null;
        }
        StringBuffer selfdata = new StringBuffer();
        // 用原始表替换自定义表
        for (int i = 0; i < data.length(); i++) {
            int j = table.indexOf(data.charAt(i));
            selfdata.append(ORIGIN_TABLE.charAt(j));
        }
        return b64decodeToStr(new String(selfdata));
    }
}
