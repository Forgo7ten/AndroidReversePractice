#include "fcrypt.h"

#define tea_DELTA 0x9e3779b9
#define xxtea_MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))


void tea_encrypt(uint32_t *origin,const uint32_t *key) {
    uint32_t v0 = origin[0], v1 = origin[1], sum = 0, i;           /* set up */
    uint32_t delta = tea_DELTA;                     /* a key schedule constant */
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];   /* cache key */
    for (i = 0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    origin[0] = v0;
    origin[1] = v1;
}

void tea_decrypt(uint32_t *origin,const uint32_t *key) {
    uint32_t v0 = origin[0], v1 = origin[1], i;  /* set up */
    uint32_t delta = tea_DELTA, sum =
            delta << 5; //32轮运算，所以是2的5次方；16轮运算，所以是2的4次方；8轮运算，所以是2的3次方/* a key schedule constant */
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];   /* cache key */
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    origin[0] = v0;
    origin[1] = v1;
}

void xtea_encrypt(unsigned int num_rounds, uint32_t *origin, const uint32_t *key) {
    unsigned int i;
    uint32_t v0 = origin[0], v1 = origin[1], sum = 0, delta = tea_DELTA;
    for (i = 0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    origin[0] = v0;
    origin[1] = v1;
}

void xtea_decrypt(unsigned int num_rounds, uint32_t *origin, const uint32_t *key) {
    unsigned int i;
    uint32_t v0 = origin[0], v1 = origin[1], delta = tea_DELTA, sum = delta * num_rounds;
    for (i = 0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    origin[0] = v0;
    origin[1] = v1;
}

void xxtea_crypt(uint32_t *origin, int n, const uint32_t *key) {
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = origin[n - 1];
        do {
            sum += tea_DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++) {
                y = origin[p + 1];
                z = origin[p] += xxtea_MX;
            }
            y = origin[0];
            z = origin[n - 1] += xxtea_MX;
        } while (--rounds);
    } else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * tea_DELTA;
        y = origin[0];
        do {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--) {
                z = origin[p - 1];
                y = origin[p] -= xxtea_MX;
            }
            z = origin[n - 1];
            y = origin[0] -= xxtea_MX;
            sum -= tea_DELTA;
        } while (--rounds);
    }
}

void tea_example() {
    uint32_t v[2] {1, 2};
    const uint32_t k[4] {2, 2, 3, 4};
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n", v[0], v[1]);
    tea_encrypt(v, k);
    printf("加密后的数据：%u %u\n", v[0], v[1]);
    tea_decrypt(v, k);
    printf("解密后的数据：%u %u\n", v[0], v[1]);
}

void xtea_example() {
    uint32_t v[2]={1,2};
    uint32_t const k[4]={2,2,3,4};
    unsigned int r=32; // num_rounds建议取值为32
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n",v[0],v[1]);
    xtea_encrypt(r, v, k);
    printf("加密后的数据：%u %u\n",v[0],v[1]);
    xtea_decrypt(r, v, k);
    printf("解密后的数据：%u %u\n",v[0],v[1]);
}

void xxtea_example() {
    uint32_t v[2] = {1, 2};
    uint32_t const k[4] = {2, 2, 3, 4};
    int n = 2; // n的绝对值表示v的长度，取正表示加密，取负表示解密
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    printf("加密前原始数据：%u %u\n", v[0], v[1]);
    xxtea_crypt(v, n, k);
    printf("加密后的数据：%u %u\n", v[0], v[1]);
    xxtea_crypt(v, -n, k);
    printf("解密后的数据：%u %u\n", v[0], v[1]);
}
