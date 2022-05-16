#ifndef FCRYPT_H
#define FCRYPT_H

#include <cstdint>
#include <iostream>
#include <cstring>

/**
 * tea加密函数
 * 32轮加密，请根据需要更改
 * @param origin 为要加密的数据是两个32位无符号整数
 * @param key 为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
 */
void tea_encrypt(uint32_t *origin, uint32_t *key);

/**
 * tea解密函数
 * 32轮解密，请根据需要更改
 * @param origin 为要加密的数据是两个32位无符号整数
 * @param key 为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
 */
void tea_decrypt(uint32_t *origin, uint32_t *key);


/**
 * tea加解密实例
 */
void tea_example();


/**
 *
 * @param num_rounds 加密轮数
 * @param origin 为要加密的数据是两个32位无符号整数
 * @param key 为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
 */
void xtea_encrypt(unsigned int num_rounds, uint32_t origin[2], uint32_t const key[4]);


/**
 * xtea解密函数
 * @param num_rounds 加密轮数
 * @param origin 为要加密的数据是两个32位无符号整数
 * @param key 为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
 */
void xtea_decrypt(unsigned int num_rounds, uint32_t origin[2], uint32_t const key[4]);

/**
 * xtea加解密实例
 */
void xtea_example();

/**
 * xxtea加解密函数，n>0加密，n<0解密
 * @param origin 为要加密的数据是两个32位无符号整数（若加密字符串先转换为16进制整数）
 * @param n 的绝对值表示v的长度(即有几个32位整数)，取正表示加密，取负表示解密
 * @param key 为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
 */
void xxtea_crypt(uint32_t *origin, int n, uint32_t const key[4]);

/**
 * xxtea加解密实例
 */
void xxtea_example();

/**
 * rc4加密函数
 * @param data 明文
 * @param data_len 明文长度
 * @param key 密钥
 * @param key_len 密钥长度
 */
void rc4_crypt(unsigned char *data, unsigned long data_len, unsigned char *key, unsigned long key_len);


/**
 * rc4加解密实例
 */
void rc4_example();

/**
 * base64编码
 * @param src 存放待编码的字符数组
 * @param dst 存放编码后的字符数组
 * @return 执行成功返回0
 */
int base64_encode(const unsigned char *src, unsigned char *dst);


/**
 * base64解码
 * @param src 存放待解码的字符数组
 * @param dst 存放解码后的字符数组
 * @return 执行成功返回0
 */
int base64_decode(const unsigned char *src, unsigned char *dst);


/**
 * base64自定义字符表编码
 * @param src 存放待编码的字符数组
 * @param dst 存放编码后的字符数组
 * @param alphabet 自定义字符表(len==65)
 */
void base64_myencode(char *src, char *dst, char *alphabet);


/**
 * base64自定义字符表解码
 * @param src 存放待解码的字符数组
 * @param dst 存放解码后的字符数组
 * @param alphabet 自定义字符表(len==65)
 */
void base64_mydecode(char *src, char *dst, char *alphabet);


/**
 * base64加解密实例
 */
void base64_example();

#endif //FCRYPT_H
