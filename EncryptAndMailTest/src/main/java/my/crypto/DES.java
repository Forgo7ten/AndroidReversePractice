package my.crypto;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * @ClassName DES
 * @Description DES加解密类
 * @Author Palmer
 * @Date 2022/2/3
 **/
public class DES {


    /**
     * 通过给予的key字节数组，生成DES秘密密钥key
     *
     * @param key 字节数组key
     * @return DES秘密密钥key
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static SecretKey getRawKey(byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
        // 实例化 密钥材料
        DESKeySpec desKey = new DESKeySpec(key);
        // 实例化 密钥生成器
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        // 生成密钥
        SecretKey secretKey = keyFactory.generateSecret(desKey);
        return secretKey;
    }

    /**
     * DES ECB 模式加密
     *
     * @param data 需要加密的数据字符串
     * @param key  加密的key
     */
    public static String desECBcrypt(byte[] data, byte[] key) {
        // 加密结果字节数组
        byte[] encrypted;
        // 加密结果字符串
        String result = null;
        if (null != key && key.length != 8) {
            System.out.println("DES uses a key length of 8 bytes (64 bits).");
            return result;
        }
        try {
            // 生成秘密密钥
            SecretKey secretKey = getRawKey(key);
            // 指定加密模式 实例化Ciper对象
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding"); // 加密方式/工作模式/填充模式
            // 初始化,设置加密(1)或解密(2)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            // 执行，得到结果字节数组
            encrypted = cipher.doFinal(data);
            // 对结果字节数组进行base64编码，得到加密后的字符串
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * DESede ECB 模式加密
     *
     * @param data 需要加密的数据字符串
     * @param key  加密的key
     */
    public static String des3ECBcrypt(byte[] data, byte[] key) {
        // 加密结果字节数组
        byte[] encrypted;
        // 加密结果字符串
        String result = null;
        if (null != key && key.length != 24) {
            System.out.println("DESede uses a key length of 24 bytes (192 bits).");
            return result;
        }
        try {
            // 实例化 密钥材料
            DESedeKeySpec desKey = new DESedeKeySpec(key);
            // 实例化 密钥生成器
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            // 生成密钥
            SecretKey secretKey = keyFactory.generateSecret(desKey);


            // 指定加密模式 实例化Ciper对象
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding"); // 加密方式/工作模式/填充模式
            // 初始化,设置加密(1)或解密(2)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            // 执行，得到结果字节数组
            encrypted = cipher.doFinal(data);
            // 对结果字节数组进行base64编码，得到加密后的字符串
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * DES CBC 模式加密
     *
     * @param data  需要加密的数据字符串
     * @param key   加密的key
     * @param keyiv CBC模式需要一个iv向量
     * @return
     */
    public static String desCBCcrypt(byte[] data, byte[] key, byte[] keyiv) {
        // 加密结果字节数组
        byte[] encrypted;
        // 加密结果字符串
        String result = null;
        if (null != key && key.length != 8) {
            System.out.println("DES uses a key length of 8 bytes (64 bits).");
            return result;
        }
        if (null != keyiv && keyiv.length != 8) {
            System.out.println("DES(CBC) uses an IV length of 8 bytes (64 bits).");
            return result;
        }
        try {
            // 生成秘密密钥
            SecretKey secretKey = getRawKey(key);
            // 指定加密模式 实例化Ciper对象
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding"); // 加密方式/工作模式/填充模式
            // CBC模式需要iv向量
            IvParameterSpec ivPS = new IvParameterSpec(keyiv);
            // 初始化,设置加密(1)或解密(2)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivPS);
            // 执行，得到结果字节数组
            encrypted = cipher.doFinal(data);
            // 对结果字节数组进行base64编码，得到加密后的字符串
            result = Base64.getEncoder().encodeToString(encrypted);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println(desECBcrypt("Forgo7ten".getBytes(StandardCharsets.UTF_8), "12345678".getBytes(StandardCharsets.UTF_8)));
        System.out.println(des3ECBcrypt("Forgo7ten".getBytes(StandardCharsets.UTF_8), "123456781234567812345678".getBytes(StandardCharsets.UTF_8)));
        System.out.println(desCBCcrypt("Forgo7ten".getBytes(StandardCharsets.UTF_8), "12345678".getBytes(StandardCharsets.UTF_8), "12345678".getBytes(StandardCharsets.UTF_8)));
    }
}