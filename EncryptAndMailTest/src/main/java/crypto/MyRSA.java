package crypto;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;

/**
 * @ClassName MyRSA
 * @Description RSA加解密
 * @Author Palmer
 * @Date 2021/7/14
 **/
public class MyRSA {

    /**
     * RSA获取公钥
     *
     * @param key 公钥ase64字符串
     * @return 解析后的公钥数据
     */
    private static PublicKey getPublicKeyBase(String key) {
        PublicKey publicKey = null;
        try {
            // 从base中读取实际的密钥字节数据
            byte[] keyBytes = MyBase.b64decodeToByte(key);
            // 通过X509(PKCS#8)解析密钥字节
            X509EncodedKeySpec KeySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory rsa = null;
            rsa = KeyFactory.getInstance("RSA");
            // 生成公钥
            publicKey = rsa.generatePublic(KeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    /**
     * RSA获取私钥
     *
     * @param key 公钥ase64字符串
     * @return 解析后的私钥数据
     */
    public static PrivateKey getPrivateKeyBase(String key) {
        PrivateKey privateKey = null;
        try {
            byte[] keyBytes = MyBase.b64decodeToByte(key);
            PKCS8EncodedKeySpec KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory rsa = null;
            rsa = KeyFactory.getInstance("RSA");
            privateKey = rsa.generatePrivate(KeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return privateKey;
    }

    /**
     * RSA使用公钥进行加密
     *
     * @param plainText    待加密的数据
     * @param publicKeyStr 加密公钥字符串(Base64编码)
     * @return 加密完成的字节数据
     */
    public static byte[] encryptBase(byte[] plainText, String publicKeyStr) {
        byte[] result = null;
        try {
            PublicKey publicKey = getPublicKeyBase(publicKeyStr);
            Cipher rsa = Cipher.getInstance("RSA/ECB/NOPADDING");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey);
            rsa.update(plainText);
            result = rsa.doFinal();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * RSA使用公钥进行加密
     *
     * @param enText        待解密的数据
     * @param privateKeyStr 解密私钥字符串(Base64编码)
     * @return 解密完成的字节数据
     */
    public static byte[] decryptBase(byte[] enText, String privateKeyStr) {
        byte[] result = null;
        try {
            PrivateKey privateKey = getPrivateKeyBase(privateKeyStr);
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, privateKey);
            rsa.update(enText);
            result = rsa.doFinal();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }


    public static void rsaBaseExample() {
        final String plainText = "RSABase64 Example";
        final String publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgrF44RJkzrmkiErk3hXADf4fE" +
                "mVHRevVSvlxWYer+sdxnZtGUXSFWta48rwMPOl2fyq/fZFYEMMqM8bBEwdXRQhdJ" +
                "K3Q/PxAF1UyqX8Lphcxz7s6FbTqKWk+5U6dwsgle/JrR54x+r2uS3q+merkF9d2i" +
                "bVjCCaedN3XilwNlxQIDAQAB";
        final String privateKeyStr = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKCsXjhEmTOuaSIS" +
                "uTeFcAN/h8SZUdF69VK+XFZh6v6x3Gdm0ZRdIVa1rjyvAw86XZ/Kr99kVgQwyozx" +
                "sETB1dFCF0krdD8/EAXVTKpfwumFzHPuzoVtOopaT7lTp3CyCV78mtHnjH6va5Le" +
                "r6Z6uQX13aJtWMIJp503deKXA2XFAgMBAAECgYBUyF+3ZUtKICBN4H9nsrvWvLbR" +
                "oO2xkiZdkSF8W5L67rOUxIaWuUXcUWYtk1QT9wJsTTHcuT9CWtSm5unSfk3qldgF" +
                "D99lu9SN4kOm6AdVfMt5R2oWmrJvgNBPLVazFlSdze1r9g5ayx6J+2rWuY5/HgAp" +
                "X61A0vAWHB/zbqPuQQJBAM6ek4burYweK0p+EHhe8OBdjWXs+WCGa66cbUribu+M" +
                "gDrrda36fF0gVE5Hx46pBAbJlgmXTWKWZpOuwRF8+CkCQQDHErVggJy8F6OfepJq" +
                "KiyzditfiMYYgrZ2DApjx3npoqrUflrw0Hd6++x7uzldhaGizmiRuMaogu0Gmndj" +
                "cqQ9AkEAsOIOuAASsJaPRxl/Lh1RJzLPvwdNQjYxb21ZHzeT8x2cFVTIDOYYm3z2" +
                "z4EhtN66pLjk6lcOF61cKWf8vuT2aQJBALSNk1PjUkSGbDDIyuLfPYvHMa+ELact" +
                "Zq/KW+IDmd79WlNABttDOBqjQuk19eGMwf0XmGASZpuPo8rJbl8UK0ECQQCHCV1G" +
                "f9aBtB8ufyvcXonLsOxRMmYCUOtoCQCpvYiRaTH83m1o0t3KG2p17+FFVqZp79b6" +
                "S8Tmb8MkvwgZMql+";
        System.out.println("明文：" + plainText);
        byte[] enbytes = encryptBase(plainText.getBytes(StandardCharsets.UTF_8), publicKeyStr);
        System.out.println("密文：" + Hex.toHexString(enbytes));
        System.out.println("======================================");
        byte[] debytes = decryptBase(enbytes, privateKeyStr);
        System.out.println("解密后：" + new String(debytes));

    }

    /**
     * RSA hex获取公钥
     * @param strN  大数N
     * @param strE  大数E
     * @return  解析好的公钥
     */
    public static PublicKey getPublicKeyHex(String strN,String strE){
        PublicKey publicKey = null;
        try {
            BigInteger N = new BigInteger(strN, 16);
            BigInteger E = new BigInteger(strE, 16);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(N, E);
            KeyFactory rsa = null;
            rsa = KeyFactory.getInstance("RSA");
             publicKey = rsa.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getprivateKeyHex(String strN,String strD){
        PrivateKey privateKey = null;
        try {
            BigInteger N = new BigInteger(strN, 16);
            BigInteger D = new BigInteger(strD, 16);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(N, D);
            KeyFactory rsa = null;
            rsa = KeyFactory.getInstance("RSA");
            privateKey = rsa.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * RSA Hex加密函数
     * @param message   待加密的消息
     * @param key   加密所需的私钥
     * @return  加密后的字节数据
     */
    public static byte[] encryptHex(String message,PrivateKey key)  {
        byte [] result = null;
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE,key);
            rsa.update(message.getBytes(StandardCharsets.UTF_8));
            result = rsa.doFinal();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * RSA Hex解密函数
     * @param entext   待解密的消息
     * @param key   解密所需的公钥
     * @return  解密后的字节数据
     */
    public static String decryptHex(byte[] entext,PublicKey key)  {
        byte [] result = null;
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE,key);
            rsa.update(entext);
            result = rsa.doFinal();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return new String(result);
    }

    public void RsaHexExample(){
        String message = "RsaHexExample";
        final String N = "cad984557c97e039431a226ad727f0c6d43ef3d418469f1b375049b229843ee9f83b1f97738ac274f5f61f401f21f1913e4b64bb31b55a38d398c0dfed00b1392f0889711c44b359e7976c617fcc734f06e3e95c26476091b52f462e79413db5";
        // N = p*q
        final String p = "d982ec7b440e2869d2535e51f91bacc3eb6eba042e106e6f875c3d17e53db65fffd6e4e9a36084ce60f83d754dd7f701";
        final String q = "eebe6dd23ce7e99c0e2249fecc4418c34af74e418bfa714c3791828414ab18f32fd7e093062a49b030225cc845f99ab5";
        // E
        final String E = "10001";
        // E*D mod (p-1)(q-1)=1
        final String D = "";
        PrivateKey privateKey = getprivateKeyHex(N, E);
        PublicKey publicKey = getPublicKeyHex(N, D);
        byte[] enbytes = encryptHex(message, privateKey);
        String s = decryptHex(enbytes, publicKey);
        System.out.println(s);
    }

    public static void main(String[] args) {
        rsaBaseExample();
    }
}
