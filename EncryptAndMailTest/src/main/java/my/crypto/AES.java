package my.crypto;


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
import java.util.Base64;

/**
 * @ClassName AES
 * @Description AES加解密类
 * @Author Palmer
 * @Date 2022/2/3
 **/
public class AES {

    /**
     * AES ECB 模式加密
     *
     * @param data 需要加密的数据字符串
     * @param key  加密的key
     * @return 加密后的被Base64编码的结果
     */
    public static String aesECBcrypt(byte[] data, byte[] key) {
        // 加密结果字节数组
        byte[] encrypted;
        // 加密结果字符串
        String result = null;
        if (null != key && !(key.length == 16 || key.length == 24 || key.length == 32)) {
            System.out.println("Invalid key length: " + key.length + " bytes\n" + "\n" + "The following algorithms will be used based on the size of the key:\n" + "  16 bytes = AES-128\n" + "  24 bytes = AES-192\n" + "  32 bytes = AES-256");
            return result;
        }
        try {
            // 实例化 aes密钥材料
            SecretKeySpec aesKey = new SecretKeySpec(key, "AES");


            // 指定加密模式 实例化Ciper对象
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // 加密方式/工作模式/填充模式
            // 初始化,设置加密(1)或解密(2)
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);

            // 执行，得到结果字节数组
            encrypted = cipher.doFinal(data);
            // 对结果字节数组进行base64编码，得到加密后的字符串
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }


    /**
     * AES CBC 模式加密
     *
     * @param data  需要加密的数据字符串
     * @param key   加密的key
     * @param keyiv CBC模式需要iv向量
     * @return 加密后的被Base64编码的结果
     */
    public static String aesCBCcrypt(byte[] data, byte[] key, byte[] keyiv) {
        // 加密结果字节数组
        byte[] encrypted;
        // 加密结果字符串
        String result = null;
        if (null != key && !(key.length == 16 || key.length == 24 || key.length == 32)) {
            System.out.println("Invalid key length: " + key.length + " bytes\n" + "\n" + "The following algorithms will be used based on the size of the key:\n" + "  16 bytes = AES-128\n" + "  24 bytes = AES-192\n" + "  32 bytes = AES-256");
            return result;
        }
        if (null != keyiv && keyiv.length != 16) {
            System.out.println("AES CBC Encrypt - Invalid IV length; got " + keyiv.length + " bytes and expected 16 bytes.");
            return result;
        }
        try {
            // 实例化 aes密钥材料
            SecretKeySpec aesKey = new SecretKeySpec(key, "AES");
            // 实例化iv向量
            IvParameterSpec aesIv = new IvParameterSpec(keyiv);

            // 指定加密模式 实例化Ciper对象
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // 加密方式/工作模式/填充模式
            // 初始化,设置加密(1)或解密(2)
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIv);

            // 执行，得到结果字节数组
            encrypted = cipher.doFinal(data);
            // 对结果字节数组进行base64编码，得到加密后的字符串
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException  e) {
            e.printStackTrace();
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println(aesECBcrypt("Forgo7ten".getBytes(StandardCharsets.UTF_8), "12345678123456781234567812345678".getBytes(StandardCharsets.UTF_8)));
        System.out.println(aesCBCcrypt("Forgo7ten".getBytes(StandardCharsets.UTF_8), "12345678123456781234567812345678".getBytes(StandardCharsets.UTF_8), "1234567812345678".getBytes(StandardCharsets.UTF_8)));

    }
}