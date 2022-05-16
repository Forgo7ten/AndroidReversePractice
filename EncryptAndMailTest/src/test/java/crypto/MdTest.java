package crypto;

import org.junit.jupiter.api.Test;

/**
 * @ClassName MdTest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MdTest {
    @Test
    public void Md5Test(){
        String data = "Md5Test";
        String s = MyMD.md5encode(data);
        assert s.equals("30c9d57f17fde9dbc06292a0cab085f4"):s;
        System.out.println("MD5encode Success："+s);
    }

    @Test
    public void Md4Test(){
        String data = "Md4Test";
        String s = MyMD.md4encode(data);
        assert s.equals("8e89f5fe28c8ec1df95af7edce1f4b29"):s;
        System.out.println("MD4encode Success："+s);
    }

    @Test
    public void test(){

    }
}
