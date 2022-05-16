package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * @ClassName MyMD
 * @Description MD系列算法
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyMD {

    static {
        // 引用BC工具类
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * md5加密
     *
     * @param data 需要加密的字节数组
     * @return 加密后的十六进制字符串(小写32位)
     */
    public static String md5encode(byte[] data) {
        String result = null;
        try {
            MessageDigest md5encoder = MessageDigest.getInstance("MD5");
            md5encoder.update(data);
            byte[] res = md5encoder.digest();
            result = Hex.toHexString(res);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * md5加密
     *
     * @param data 需要加密的字符串
     * @return 加密后的十六进制字符串(小写32位)
     */
    public static String md5encode(String data) {
        return md5encode(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * md4加密
     *
     * @param data 需要加密的字节数组
     * @return 加密后的十六进制字符串(小写32位)
     */
    public static String md4encode(byte[] data) {
        String result = null;
        try {
            MessageDigest md4encoder = MessageDigest.getInstance("MD4", "BC");
            md4encoder.update(data);
            byte[] res = md4encoder.digest();
            result = Hex.toHexString(res);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * md4加密
     *
     * @param data 需要加密的字符串
     * @return 加密后的十六进制字符串(小写32位)
     */
    public static String md4encode(String data) {
        return md4encode(data.getBytes(StandardCharsets.UTF_8));
    }


}
