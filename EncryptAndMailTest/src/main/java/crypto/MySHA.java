package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @ClassName MySHA
 * @Description SHA系列算法
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MySHA {

    static {
        // 引用BC工具类
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * SHA-256加密算法
     *
     * @param data 待加密的字节数组
     * @return 加密后的十六进制字符串(len = 64)
     */
    public static String sha256encode(byte[] data) {
        String result = null;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(data);
            byte[] res = sha.digest();
            result = Hex.toHexString(res);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * SHA-256加密算法
     *
     * @param data 待加密的字符串
     * @return 加密后的十六进制字符串(len = 64)
     */
    public static String sha256encode(String data) {
        return sha256encode(data.getBytes(StandardCharsets.UTF_8));
    }
}
