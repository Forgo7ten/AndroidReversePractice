#include "fcrypt.h"


int base64_encode(const unsigned char *src, unsigned char *dst) {

    size_t len = strlen((const char *) src);
    static unsigned char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    while (len > 2) {
        *dst++ = base64char[src[0] >> 2 & 0x3f];
        *dst++ = base64char[(src[0] & 0x3) << 4 | src[1] >> 4 & 0xf];
        *dst++ = base64char[(src[1] & 0xf) << 2 | src[2] >> 6 & 0x3];
        *dst++ = base64char[src[2] & 0x3f];
        len -= 3;
        src += 3;
    }

    if (len) {
        *dst++ = base64char[src[0] >> 2 & 0x3f];
        if (len > 1) {
            *dst++ = base64char[((src[0] & 0x3) << 4) | ((src[1] >> 4) & 0xf)];
            *dst++ = base64char[(src[1] & 0xf) << 2];
        } else {
            *dst++ = base64char[(src[0] & 0x3) << 4];
            *dst++ = '=';
        }
        *dst++ = '=';
    }

    *dst = 0;
    return 0;
}


int base64_decode(const unsigned char *src, unsigned char *dst) {
    static char base64char[] = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    };

    int i;
    size_t len = strlen((const char *) src);

    for (i = 0; i < len; i++) {
        if (src[i] == -1) {
            return 1; //unexpected characters
        } else if (src[i] == '=') {
            len = i;
        }
    }

    if (len % 4 == 1) {
        return 2;
    }

    while (len > 3) {
        *dst++ = (unsigned char) (base64char[src[0]] << 2) | (base64char[src[1]] >> 4 & 0x3);
        *dst++ = (unsigned char) (base64char[src[1]] << 4) | (base64char[src[2]] >> 2 & 0xf);
        *dst++ = (unsigned char) (base64char[src[2]] << 6) | (base64char[src[3]]);

        src += 4;
        len -= 4;
    }

    if (len) {
        if (len > 1) {
            *dst++ = (base64char[src[0]] << 2) | (base64char[src[1]] >> 4 & 0x3);
        }

        if (len > 2) {
            *dst++ = (base64char[src[1]] << 4) | (base64char[src[2]] >> 2 & 0xf);
        }

    }
    *dst = 0;
    return 0;
}

void base64_myencode(char *src, char *dst, char *alphabet) {
    if (strlen(alphabet) != 65) {
        std::cout << "Invalid Base64 alphabet length (" << strlen(alphabet) << "): need 65" << std::endl;
        return;
    }
    base64_encode((const unsigned char *) src, (unsigned char *) dst);
    int i, j;
    char base64_table[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    int len_s = strlen(dst);
    for (i = 0; i < len_s; i++) {
        for (j = 0; j < 65; j++) {
            if (dst[i] == base64_table[j]) {
                dst[i] = alphabet[j];
                break;
            }
        }
    }
}

void base64_mydecode(char *src, char *dst, char *alphabet) {
    if (strlen(alphabet) != 65) {
        std::cout << "Invalid Base64 alphabet length (" << strlen(alphabet) << "): need 65" << std::endl;
        return;
    }
    int i, j;
    char base64_table[66] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    int len_s = strlen(src);
    for (i = 0; i < len_s; i++) {
        for (j = 0; j < 65; j++) {
            if (src[i] == alphabet[j]) {
                src[i] = base64_table[j];
                break;
            }
        }
    }
    base64_decode((const unsigned char *) src, (unsigned char *) dst);
}


void base64_example() {
    char plain[30]{"Forgo7ten"};
    char enout[40]{};
    char deout[40]{};
    char table[66]{"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="};
    base64_myencode(plain, enout, table);
    std::cout << enout << std::endl;
    base64_mydecode(enout, deout, table);
    std::cout << deout << std::endl;
}
