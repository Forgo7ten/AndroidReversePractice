package crypto;

import org.junit.jupiter.api.Test;

/**
 * @ClassName MySHATest
 * @Description //TODO
 * @Author Palmer
 * @Date 2021/7/13
 **/
public class MySHATest {
    @Test
    public void Sha256Test(){
        String data = "Sha256Test";
        String s = MySHA.sha256encode(data);
        assert s.equals("6533451da188a51481104a54ae14a07716f1247281a1739718a820ad98d80772"):s;
        System.out.println("Sha256encode Success："+s);
    }
}
