package my.test;

/**
 * @ClassName TestMain
 * @Description //TODO
 * @Author Palmer
 * @Date 2022/1/11
 **/
public class TestMain {
    public static byte[] a(byte[] bArr, long j) {
        for (int i = 0; ((long) i) < j; i++) {
            for (int i2 = 0; i2 < bArr.length; i2++) {
                bArr[i2] = (byte) (((bArr[i2] >> 4) & 15) + ((bArr[i2] & 15) << 4));
            }
            for (int length = bArr.length - 1; length >= 0; length--) {
                if (length != 0) {
                    bArr[length] = (byte) (bArr[length] ^ bArr[length - 1]);
                } else {
                    bArr[length] = (byte) (bArr[length] ^ bArr[bArr.length - 1]);
                }
                bArr[length] = (byte) (bArr[length] ^ 150);
            }
            for (int length2 = bArr.length - 1; length2 >= 0; length2--) {
                if (length2 != 0) {
                    bArr[length2] = (byte) (bArr[length2] - bArr[length2 - 1]);
                } else {
                    bArr[length2] = (byte) (bArr[length2] - bArr[bArr.length - 1]);
                }
                bArr[length2] = (byte) (bArr[length2] - 58);
            }
        }
        return bArr;
    }


    public static void main(String[] args) {
        System.out.println(Test2.a);
    }
    public static void printBytes(byte[] arr){
        StringBuffer sb = new StringBuffer();
        for(int i=0;i<arr.length;++i){
            System.out.print(String.format("%x ",arr[i]));
        }

    }

}