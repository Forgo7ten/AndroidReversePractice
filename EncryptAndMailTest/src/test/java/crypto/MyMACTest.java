package crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * @ClassName MyMACTest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MyMACTest {
    @Test
    public void HmacSHA1Test(){
        String s = MyMAC.macSHA1encode("a12345678".getBytes(StandardCharsets.UTF_8), "1234567890".getBytes(StandardCharsets.UTF_8));
        System.out.println(s);
    }
}
