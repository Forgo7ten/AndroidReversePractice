package crypto;

import org.junit.jupiter.api.Test;

/**
 * @ClassName MyDESTest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyDESTest {
    @Test
    public void DescryptTest(){
        String data = "DescryptTest";
        String key = "12345678";
        String s = MyDES.DESencryptToBase64(data, key, MyDES.DES_ALGORITHM, MyDES.ECB_MODEL, MyDES.PKCS5_PADDING);
        System.out.println(s);
        s = MyDES.DESdecryptFromBase64ToStr(s, key, MyDES.DES_ALGORITHM, MyDES.ECB_MODEL, MyDES.PKCS5_PADDING);
        System.out.println(s);

    }

    public static void main(String[] args) {
        MyDES.desExample();
    }
}
