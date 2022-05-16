package my.crypto;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * @ClassName RSA
 * @Description //TODO
 * @Author Palmer
 * @Date 2022/2/6
 **/
public class RSA {

    /**
     * RSA 通过Base64获取公钥
     *
     * @param key 公钥base64字符串(pkcs8)
     * @return 解析后的公钥
     */
    private static PublicKey getPublicKeyFromBase64(String key) {
        PublicKey publicKey = null;
        try {
            // 从base中读取实际的密钥字节数据
            byte[] keyBytes = Base64.getDecoder().decode(key);
            // 通过X509解析密钥(PKCS#8)字节
            X509EncodedKeySpec KeySpec = new X509EncodedKeySpec(keyBytes);
            /* Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys */
            KeyFactory rsa = KeyFactory.getInstance("RSA");
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
     * RSA 通过Base64获取私钥
     *
     * @param key 公钥ase64字符串(pkcs8)
     * @return 解析后的私钥
     */
    public static PrivateKey getPrivateKeyFromBase64(String key) {
        PrivateKey privateKey = null;
        try {
            // 从base中读取实际的密钥字节数据
            byte[] keyBytes = Base64.getDecoder().decode(key);
            // 通过PKCS8解析密钥(PKCS#8)字节
            PKCS8EncodedKeySpec KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            /* Only RSAPrivate(Crt)KeySpec and PKCS8EncodedKeySpec supported for RSA private keys */
            // 生成rsa KeyFactory实例
            KeyFactory rsa = KeyFactory.getInstance("RSA");
            // 产生私钥
            privateKey = rsa.generatePrivate(KeySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return privateKey;
    }

    /**
     * 从16进制大数中获取RSA公钥
     *
     * @param strN 十六进制大数N
     * @param strE 十六进制大数E
     * @return 解析后的公钥
     */
    public static PublicKey getPublicKeyFromHex(String strN, String strE) {
        PublicKey publicKey = null;
        try {
            BigInteger N = new BigInteger(strN, 16);
            BigInteger E = new BigInteger(strE, 16);
            // 通过大数来生成RSA KeySpec
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(N, E);
            KeyFactory rsa = KeyFactory.getInstance("RSA");
            publicKey = rsa.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    /**
     * 从16进制大数中获取RSA私钥
     *
     * @param strN 十六进制大数N
     * @param strD 十六进制大数D
     * @return 解析后的私钥
     */
    public static PrivateKey getprivateKeyFromHex(String strN, String strD) {
        PrivateKey privateKey = null;
        try {
            BigInteger N = new BigInteger(strN, 16);
            BigInteger D = new BigInteger(strD, 16);
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(N, D);
            KeyFactory rsa = KeyFactory.getInstance("RSA");
            privateKey = rsa.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * rsa加密函数
     *
     * @param plainText 待加密的明文字节
     * @param key       可传公钥或者私钥，但只有另一个才能解密
     * @return 加密后的字节数组
     */
    public static byte[] rsaEncrypt(byte[] plainText, Key key) {
        byte[] result = null;
        try {
            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.ENCRYPT_MODE, key);
            rsa.update(plainText);
            result = rsa.doFinal();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }


    /**
     * rsa解密函数
     *
     * @param enText 待解密的密文字节
     * @param key    可传公钥或者私钥，但只有另一个才能加密
     * @return 解密后的字节数组
     */
    public static byte[] rsaDecrypt(byte[] enText, Key key) {
        byte[] result = null;
        try {

            Cipher rsa = Cipher.getInstance("RSA");
            rsa.init(Cipher.DECRYPT_MODE, key);
            rsa.update(enText);
            result = rsa.doFinal();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return result;
    }


    public static void rsaBaseExample() {

        final String plainText = "RSABase64 Example";
        String privateKeyStr = "MIIB5QIBADANBgkqhkiG9w0BAQEFAASCAc8wggHLAgEAAmEAytmEVXyX4DlDGiJq1yfwxtQ+89QYRp8bN1BJsimEPun4Ox+Xc4rCdPX2H0AfIfGRPktkuzG1WjjTmMDf7QCxOS8IiXEcRLNZ55dsYX/Mc08G4+lcJkdgkbUvRi55QT21AgMBAAECYHQN5IdgRCg1uq1eGZBFOp0W23l20/i7mL+ZwMAcvpucErgIyAaD0eNGwWx5rBYodPKMphDBuX5eH/rpVyXODGsDHD4YixcYenk7MizEAExWjnbJslhULqKi1uzUYv/0AQIxANmC7HtEDihp0lNeUfkbrMPrbroELhBub4dcPRflPbZf/9bk6aNghM5g+D11Tdf3AQIxAO6+bdI85+mcDiJJ/sxEGMNK905Bi/pxTDeRgoQUqxjzL9fgkwYqSbAwIlzIRfmatQIxAJdaLfncMknW0N7oG/xOUJqH4aWYsQEIB51WBsDw6E9WX60F3rmruN3uxe3mCUPFAQIxAKcR7/xdztT19hYcvgfn54RS47mJuRErU/DXDQStCgbNt79UUs7PrP100bcoF3/SuQIwfon6rz94rZWL68Zdz3bNIemUjiuyGoG+EJ+sNyu0G67tvfxnV3P6TLXFzhk7Xtuc";
        String publicKeyStr = "MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAMrZhFV8l+A5Qxoiatcn8MbUPvPUGEafGzdQSbIphD7p+Dsfl3OKwnT19h9AHyHxkT5LZLsxtVo405jA3+0AsTkvCIlxHESzWeeXbGF/zHNPBuPpXCZHYJG1L0YueUE9tQIDAQAB";

        // 从base64字符串中解析公钥和私钥
        PrivateKey privateKey = getPrivateKeyFromBase64(privateKeyStr);
        PublicKey publicKey = getPublicKeyFromBase64(publicKeyStr);
        System.out.println("privateKey：" + Hex.toHexString(privateKey.getEncoded()));
        System.out.println("publicKey：" + Hex.toHexString(publicKey.getEncoded()));

        System.out.println("明文：" + plainText);
        // 使用公钥加密
        byte[] enbytes = rsaEncrypt(plainText.getBytes(StandardCharsets.UTF_8), publicKey);
        System.out.println("密文：" + Hex.toHexString(enbytes));
        // 使用私钥解密
        byte[] debytes = rsaDecrypt(enbytes, privateKey);
        System.out.println("解密后：" + new String(debytes));

    }

    public static void rsaHexExample() {
        String message = "RsaHexExample";
        final String N = "cad984557c97e039431a226ad727f0c6d43ef3d418469f1b375049b229843ee9f83b1f97738ac274f5f61f401f21f1913e4b64bb31b55a38d398c0dfed00b1392f0889711c44b359e7976c617fcc734f06e3e95c26476091b52f462e79413db5";
        // N = p*q
        final String p = "d982ec7b440e2869d2535e51f91bacc3eb6eba042e106e6f875c3d17e53db65fffd6e4e9a36084ce60f83d754dd7f701";
        final String q = "eebe6dd23ce7e99c0e2249fecc4418c34af74e418bfa714c3791828414ab18f32fd7e093062a49b030225cc845f99ab5";
        // E
        final String E = "10001";
        // E*D mod (p-1)(q-1)=1
        final String D = "740de48760442835baad5e1990453a9d16db7976d3f8bb98bf99c0c01cbe9b9c12b808c80683d1e346c16c79ac162874f28ca610c1b97e5e1ffae95725ce0c6b031c3e188b17187a793b322cc4004c568e76c9b258542ea2a2d6ecd462fff401";

        // 从大数字符串中解析公钥和私钥
        PrivateKey privateKey = getprivateKeyFromHex(N, D);
        PublicKey publicKey = getPublicKeyFromHex(N, E);
        System.out.println("privateKey：" + Hex.toHexString(privateKey.getEncoded()));
        System.out.println("publicKey：" + Hex.toHexString(publicKey.getEncoded()));

        System.out.println("明文：" + message);
        // 使用私钥加密
        byte[] enbytes = rsaEncrypt(message.getBytes(StandardCharsets.UTF_8), privateKey);
        System.out.println("密文：" + Hex.toHexString(enbytes));
        // 使用公钥解密
        byte[] debytes = rsaDecrypt(enbytes, publicKey);
        System.out.println("解密后：" + new String(debytes));
    }


    public static void main(String[] args) {
        rsaBaseExample();
        System.out.println("============================================================================");
        rsaHexExample();
    }

}