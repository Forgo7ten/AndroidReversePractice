package crypto;


import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * @ClassName MyDES
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyDES {

    /**
     * 设置DES为加密模式
     */
    public static final int DES_ENCRYPT_MODEL = 1;
    /**
     * 设置DES为解密模式
     */
    public static final int DES_DECRYPT_MODEL = 2;

    /**
     * 设置DES加解密
     */
    public static final String DES_ALGORITHM = "DES";

    /**
     * 设置DESede加解密
     */
    public static final String DESEDE_ALGORITHM = "DESede";

    /**
     * ECB模式
     */
    public static final String ECB_MODEL = "ECB";

    /**
     * 填充方式：PKCS5Padding
     */
    public static final String PKCS5_PADDING = "PKCS5Padding";


    /**
     * DES加解密
     *
     * @param data      待加解密的数据
     * @param keyBytes  密钥key 字节数组
     * @param flag      标志位，标识加密(1)或解密(2)
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return 加解密完成后的字节数组
     */
    public static byte[] desCrypt(byte[] data, byte[] keyBytes, int flag, String algorithm, String model, String padding) {
        byte[] bytes = null;
        try {
            // 实例化 密钥材料
            DESKeySpec desKey = new DESKeySpec(keyBytes);
            // 实例化 密钥生成器
            SecretKeyFactory des = SecretKeyFactory.getInstance(algorithm);
            // 生成密钥
            SecretKey secretKey = des.generateSecret(desKey);
            // 指定加密模式 实例化
            Cipher cipher = Cipher.getInstance(algorithm + "/" + model + "/" + padding);
            // 初始化,设置加密或解密
            cipher.init(flag, secretKey);
            bytes = cipher.doFinal(data);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    /**
     * 加密为Base64
     *
     * @param data      需加密的字节数组
     * @param keyBytes  key字节数组
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return
     */
    public static String DESencryptToBase64(byte[] data, byte[] keyBytes, String algorithm, String model, String padding) {
        byte[] bytes = desCrypt(data, keyBytes, DES_ENCRYPT_MODEL, algorithm, model, padding);
        return MyBase.b64encodeToStr(bytes);
    }

    /**
     * 加密为Base64
     *
     * @param data      需加密的字符串
     * @param key       key字符串
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return
     */
    public static String DESencryptToBase64(String data, String key, String algorithm, String model, String padding) {
        byte[] bytes = desCrypt(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), DES_ENCRYPT_MODEL, algorithm, model, padding);
        return MyBase.b64encodeToStr(bytes);
    }


    /**
     * 从Base64中解密
     *
     * @param data      需解密的字节数组
     * @param keyBytes  key字节数组
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return 解密后的字节数组
     */
    public static byte[] DESdecryptFromBase64ToByte(byte[] data, byte[] keyBytes, String algorithm, String model, String padding) {
        byte[] bytes = MyBase.b64decodeToByte(data);
        byte[] res = desCrypt(bytes, keyBytes, DES_DECRYPT_MODEL, algorithm, model, padding);
        return res;
    }

    /**
     * 从Base64中解密
     *
     * @param data      需解密的字符串
     * @param key       key字符串
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return 解密后的字符串
     */
    public static String DESdecryptFromBase64ToStr(String data, String key, String algorithm, String model, String padding) {
        byte[] bytes = DESdecryptFromBase64ToByte(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), algorithm, model, padding);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * 从Base64中解密
     *
     * @param data      需解密的字符串
     * @param key       key字符串
     * @param algorithm 算法
     * @param model     模式
     * @param padding   填充方式
     * @return 解密后的字节数组
     */
    public static byte[] DESdecryptFromBase64ToByte(String data, String key, String algorithm, String model, String padding) {
        byte[] bytes = DESdecryptFromBase64ToByte(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), algorithm, model, padding);
        return bytes;
    }


    /**
     * DESede加密
     *
     * @param data 待加密的字符串
     * @param key  所需的key
     * @return 加密后经过base64编码的字符串
     */
    public static String DESedeEncryptToBase64(String data, String key) {
        byte[] bytes = DESdecryptFromBase64ToByte(data.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8), DESEDE_ALGORITHM, ECB_MODEL, PKCS5_PADDING);
        return MyBase.b64encodeToStr(bytes);
    }


    /**
     * DES加密例子
     */
    public static void desExample() {
        // 待加密的明文
        String data = "desExample";
        // key长度为64位
        String key = "12345678";
        byte[] bytes = null;
        try {
            // 实例化 密钥材料
            DESKeySpec desKey = new DESKeySpec(key.getBytes(StandardCharsets.UTF_8));
            // 实例化 密钥生成器
            SecretKeyFactory des = SecretKeyFactory.getInstance("DES");
            // 生成密钥
            SecretKey secretKey = des.generateSecret(desKey);
            // 指定加密模式 实例化
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            // 初始化,设置加密(1)或解密
            cipher.init(1, secretKey);
            bytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        String result = Base64.getEncoder().encodeToString(bytes);
        System.out.println(result);
    }
}
