#include "fcrypt.h"


/**
 * rc4初始化函数(init)
 * @param S
 * @param key 密钥key
 * @param key_len
 */
void rc4_init(unsigned char *S, unsigned char *key, unsigned long key_len);

/**
 * rc4 prga生成密钥流并加密
 * @param S 初始化后的S盒
 * @param data 需要加密的明文，加密后存放此处
 * @param data_len 明文长度
 */
void rc4_prga(unsigned char *S, unsigned char *data, unsigned long data_len);


void rc4_init(unsigned char *S, unsigned char *key, unsigned long key_len) {
    int i = 0, j = 0;
    char T[256] = {0};
    unsigned char tmp = 0;
    for (i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = key[i % key_len];
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;

        tmp = S[i];
        S[i] = S[j]; //交换s[i]和s[j]
        S[j] = tmp;
    }
}

void rc4_prga(unsigned char *S, unsigned char *data, unsigned long data_len) {
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp, ckey;
    for (k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        tmp = S[i];
        S[i] = S[j]; //交换s[x]和s[y]
        S[j] = tmp;

        t = (S[i] + S[j]) % 256;
        ckey = S[t];
        data[k] ^= ckey;
    }
}

void rc4_crypt(unsigned char *data, unsigned long data_len, unsigned char *key, unsigned long key_len) {
    unsigned char s[256];
    rc4_init(s, key, key_len);
    rc4_prga(s, data, data_len);
}


void rc4_example() {
    unsigned char data[]{"1234"};
    unsigned long data_len = 4;
    unsigned char key[]{"abcd"};
    unsigned long key_len = 4;
    std::cout << std::hex;
    std::cout << "加密前：";
    for (int i = 0; i < data_len; ++i) {
        std::cout << (int) data[i] << " ";
    }
    std::cout << std::endl;
    // 进行rc4加密
    rc4_crypt(data, data_len, key, key_len);
    // 加密结果的打印
    std::cout << "加密后：";
    for (int i = 0; i < data_len; ++i) {
        std::cout << (int) data[i] << " ";
    }
    std::cout << std::endl;
    // 进行rc4解密
    rc4_crypt(data, data_len, key, key_len);
    // 打印解密结果
    std::cout << "解密后：";
    for (int i = 0; i < data_len; ++i) {
        std::cout << (int) data[i] << " ";
    }
    std::cout << std::endl;
}





