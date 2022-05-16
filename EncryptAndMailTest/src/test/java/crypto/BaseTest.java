package crypto;

import org.junit.jupiter.api.Test;


/**
 * @ClassName BaseTest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/12
 **/
public class BaseTest {
    public void base64Test(){
        String origin = "base64Test";
        String s = MyBase.b64encodeToStr(origin);
        assert s.equals("YmFzZTY0VGVzdA=="):"Encode Failed";
        System.out.println("Encode Success");
        String destr = MyBase.b64decodeToStr(s);
        assert destr.equals(origin):"Decode Failed";
        System.out.println("Decode Success");
    }

    @Test
    public void base64selfTest(){
        String origin = "base64selfTest";
        String table = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/=";
        String s = MyBase.b64encodeSelf(origin,table);
        assert s.equals("oC5PpjoQsSlIpBhBsTg="):s+" EncodeSelf Failed";
        System.out.println("EncodeSelf Success");
        String destr = MyBase.b64decodeSelf(s,table);
        assert destr.equals(origin):"DecodeSelf Failed";
        System.out.println("DecodeSelf Success");
    }

    @Test
    public void ttiTest(){
        byte[] a = new byte[]{-120, 77, -14, -38, 17, 5, -42, 44, (byte)0xE0, 109, 85, 0x1F, 24, -91, (byte)0x90, -83, 0x40, -83, (byte)0x80, 84, 5, -94, -98, -30, 18, 70, -26, 71, 5, -99, -62, -58, 0x75, 29, -44, 6, 0x70, -4, 81, 84, 9, 22, -51, 0x5F, -34, 12, 0x2F, 77};
        String s = MyBase.b64encodeToStr(a);
        System.out.println(s);

    }
}
