package crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName MyAES
 * @Description AES加解密
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyAES {
    public static byte[] aesCrypt(byte[] data, byte[] keyBytes, byte[] iv, int flag, String algorithm, String model, String padding) {
        byte[] bytes = null;
        try {
            SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");
            IvParameterSpec aesIv = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(algorithm + "/" + model + "/" + padding);
            cipher.init(flag, aesKey, aesIv);
            cipher.update(data);
            bytes = cipher.doFinal();
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return bytes;
    }


    /**
     * DES加密例子
     */
    public static void aesExample() {
        // 待加密的明文
        String data = "aesExample";
        // key注意
        String key = "12345678123456781234567812345678";
        String iv = "0123456789abcdef";
        byte[] bytes = null;
        try {
            SecretKeySpec aesKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            IvParameterSpec aesIv = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv);
            cipher.update(data.getBytes(StandardCharsets.UTF_8));
            bytes = cipher.doFinal();
        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        String result = MyBase.b64encodeToStr(bytes);
        System.out.println(result);
    }
}
