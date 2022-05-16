package crypto;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;


/**
 * @ClassName MyRSATest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/14
 **/
public class MyRSATest {
    @Test
    public void rsaTest(){
        MyRSA.rsaBaseExample();
    }
    @Test
    public void rsaBaseExample() {
        final String plainText = "D925902A381B76BA5A4E781BAC9034C3CAFBC2328646B5A4814AD6D10D4E32E14B2DAB106D278C6C7E0521620C6E4A3E450DCD6689D0277B";
        final String publicKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDQKFDQWLx8tLUQoqtNLht28fPhBtCu0dfOF5qOJI/DVh8Jfv7axJV9Nx+UT/VTj8cIhd6SkFQnqxWlhEEWjSMPMjWQlj4RFqPKGkGGTP3e+/adnmK2LqMqNWf6l1zfvSORg6yUi+YU79r2fMT3Dt0OCl+9exL/9kYtFUd/47RTOQIDAQAB";
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
        byte[] origin = new byte[0x80];
        System.arraycopy(plainText.getBytes(StandardCharsets.UTF_8),0,origin,0,plainText.getBytes(StandardCharsets.UTF_8).length);
        byte[] enbytes = MyRSA.encryptBase(origin, publicKeyStr);

        System.out.println("密文Hex：" + Hex.toHexString(enbytes));
        System.out.println("密文Base64：" + Base64.encodeBase64String(enbytes));
        System.out.println("======================================");
//        byte[] debytes = MyRSA.decryptBase(enbytes, privateKeyStr);
//        System.out.println("解密后：" + new String(debytes));

    }

}
