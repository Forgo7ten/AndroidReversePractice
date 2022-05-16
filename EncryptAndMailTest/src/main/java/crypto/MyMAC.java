package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * @ClassName MyMAC
 * @Description MAC系列算法
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyMAC {
    static {
        // 引用BC工具类
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * HmacSHA1加密
     *
     * @param data     加密的字符数组
     * @param keyBytes key字符数组
     * @return 加密后的十六进制字符串(len=40)
     */
    public static String macSHA1encode(byte[] data, byte[] keyBytes) {
        String result =null;
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA1");
            Mac mac = Mac.getInstance(key.getAlgorithm());
            // 同Mac.getInstance("HmacSHA1");
            mac.init(key);
            mac.update(data);
            byte[] res = mac.doFinal();
            result = Hex.toHexString(res);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return result;
    }
}
