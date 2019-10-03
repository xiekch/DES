#include "DES.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define KEYBYTES 8
#define MESSBYTES 8
#define KEYLEN 64
#define MESSLEN 64

typedef struct Key {
    unsigned char k[8];
    unsigned char c[4];
    unsigned char d[4];
    // unsigned char cd[8];
} Key;

const int IP[] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                  57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
                  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

const int IPReverse[] = {40, 8,  48, 16, 56, 24, 64, 32, 39, 7,  47, 15, 55,
                         23, 63, 31, 38, 6,  46, 14, 54, 22, 62, 30, 37, 5,
                         45, 13, 53, 21, 61, 29, 36, 4,  44, 12, 52, 20, 60,
                         28, 35, 3,  43, 11, 51, 19, 59, 27, 34, 2,  42, 10,
                         50, 18, 58, 26, 33, 1,  41, 9,  49, 17, 57, 25};

const int messageE[] = {32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
                        8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

const int SBox1[] = {14, 4,  13, 1, 2,  15, 11, 8,  3,  10, 6,  12, 5,
                     9,  0,  7,  0, 15, 7,  4,  14, 2,  13, 1,  10, 6,
                     12, 11, 9,  5, 3,  8,  4,  1,  14, 8,  13, 6,  2,
                     11, 15, 12, 9, 7,  3,  10, 5,  0,  15, 12, 8,  2,
                     4,  9,  1,  7, 5,  11, 3,  14, 10, 0,  6,  13};

const int SBox2[] = {15, 1,  8,  14, 6,  11, 3, 4,  9,  7,  2,  13, 12,
                     0,  5,  10, 3,  13, 4,  7, 15, 2,  8,  14, 12, 0,
                     1,  10, 6,  9,  11, 5,  0, 14, 7,  11, 10, 4,  13,
                     1,  5,  8,  12, 6,  9,  3, 2,  15, 13, 8,  10, 1,
                     3,  15, 4,  2,  11, 6,  7, 12, 0,  5,  14, 9};

const int SBox3[] = {10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11,
                     4,  2,  8,  13, 7,  0,  9,  3,  4,  6,  10, 2,  8,
                     5,  14, 12, 11, 15, 1,  13, 6,  4,  9,  8,  15, 3,
                     0,  11, 1,  2,  12, 5,  10, 14, 7,  1,  10, 13, 0,
                     6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12};

const int SBox4[] = {7,  13, 14, 3,  0,  6,  9,  10, 1,  2, 8,  5,  11,
                     12, 4,  15, 13, 8,  11, 5,  6,  15, 0, 3,  4,  7,
                     2,  12, 1,  10, 14, 9,  10, 6,  9,  0, 12, 11, 7,
                     13, 15, 1,  3,  14, 5,  2,  8,  4,  3, 15, 0,  6,
                     10, 1,  13, 8,  9,  4,  5,  11, 12, 7, 2,  14};

const int SBox5[] = {2,  12, 4, 1,  7,  10, 11, 6, 8,  5,  3,  15, 13,
                     0,  14, 9, 14, 11, 2,  12, 4, 7,  13, 1,  5,  0,
                     15, 10, 3, 9,  8,  6,  4,  2, 1,  11, 10, 13, 7,
                     8,  15, 9, 12, 5,  6,  3,  0, 14, 11, 8,  12, 7,
                     1,  14, 2, 13, 6,  15, 0,  9, 10, 4,  5,  3};

const int SBox6[] = {12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3, 4, 14,
                     7,  5,  11, 10, 15, 4,  2,  7,  12, 9,  5, 6, 1,
                     13, 14, 0,  11, 3,  8,  9,  14, 15, 5,  2, 8, 12,
                     3,  7,  0,  4,  10, 1,  13, 11, 6,  4,  3, 2, 12,
                     9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8, 13};

const int SBox7[] = {4,  11, 2,  14, 15, 0,  8, 13, 3,  12, 9,  7,  5,
                     10, 6,  1,  13, 0,  11, 7, 4,  9,  1,  10, 14, 3,
                     5,  12, 2,  15, 8,  6,  1, 4,  11, 13, 12, 3,  7,
                     14, 10, 15, 6,  8,  0,  5, 9,  2,  6,  11, 13, 8,
                     1,  4,  10, 7,  9,  5,  0, 15, 14, 2,  3,  12};

const int SBox8[] = {13, 2,  8, 4,  6,  15, 11, 1,  10, 9, 3, 14, 5,
                     0,  12, 7, 1,  15, 13, 8,  10, 3,  7, 4, 12, 5,
                     6,  11, 0, 14, 9,  2,  7,  11, 4,  1, 9, 12, 14,
                     2,  0,  6, 10, 13, 15, 3,  5,  8,  2, 1, 14, 7,
                     4,  10, 8, 13, 15, 12, 9,  0,  3,  5, 6, 11};

const int *SBoxes[] = {SBox1, SBox2, SBox3, SBox4, SBox5, SBox6, SBox7, SBox8};

const int keyPC1[] = {57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
                      10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
                      63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
                      14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4};

const int keyPC2[] = {14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
                      23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
                      41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                      44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};

void permute(const unsigned char *data, const int *permTable, int len,
             unsigned char *result) {
    unsigned char bit = 0;
    for (int i = 0; i < len; i++) {
        bit =
            data[(permTable[i] - 1) / 8] & (0x80u >> ((permTable[i] - 1) % 8));
        if (bit)
            result[i / 8] |= 0x80u >> (i % 8);
    }
}

// bit shift, avoid hardware-related shift (big end/little end)
void cycleShift(const unsigned char *data, int shiftBits, int len,
           unsigned char *result) {
    // shiftBits > 0 : left shift
    unsigned char temp = (data[0] & (0xff << (8 - shiftBits)));

    unsigned char bit = 0;
    for (int i = 0; i < len; i++) {
        bit = data[(i + shiftBits) / 8] & (0x80u >> ((i + shiftBits) % 8));
        if (bit)
            result[i / 8] |= 0x80u >> (i % 8);
    }
    result[(len - 1) / 8] |= temp >> ((len % 8) - shiftBits);
}

Key *generateSubKey(unsigned char *key) {
    Key *keys = (Key *)calloc(17, sizeof(Key));
    permute(key, keyPC1, 28, keys[0].c);
    permute(key, keyPC1 + 28, 28, keys[0].d);

    unsigned char buffer[10];
    int shiftBits;
    for (int i = 1; i <= 16; i++) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            shiftBits = 1;
        } else {
            shiftBits = 2;
        }
        cycleShift(keys[i - 1].c, shiftBits, 28, keys[i].c);
        cycleShift(keys[i - 1].d, shiftBits, 28, keys[i].d);

        strncpy(buffer, keys[i].c, 4);
        shiftBits = 4;
        unsigned char temp = (keys[i].d[0] & (0xff << (8 - shiftBits)));
        cycleShift(keys[i].d, 4, 28, buffer + 4);
        buffer[3] |= temp >> 4;

        permute(buffer, keyPC2, 48, keys[i].k);
    }

    return keys;
}

void process(unsigned char *data, unsigned char *key) {}

void encrypt(const char *keyFileName, const char *plainFileName,
             const char *cipherFileName) {
    FILE *keyFile = fopen(keyFileName, "rb");
    FILE *plainFile = fopen(plainFileName, "rb");
    FILE *cipherFile = fopen(cipherFileName, "wb");
    if (keyFile == NULL || plainFile == NULL || cipherFile == NULL) {
        fprintf(stderr, "File open error\n");
        exit(1);
    }

    unsigned char key[KEYBYTES + 10];
    int readCount = 0;
    readCount = fread(key, 1, KEYBYTES, keyFile);
    if (readCount != KEYBYTES) {
        fprintf(stderr, "Key is too short\n");
        exit(1);
    }
    fclose(keyFile);

    fseek(plainFile, 0, SEEK_END);
    int file_size = ftell(plainFile);
    fseek(plainFile, 0, SEEK_SET);
    int lastCount = file_size / 8 + ((file_size % 8) ? 1 : 0);
    unsigned char readBuffer[MESSBYTES + 10];
    unsigned char writeBuffer[MESSBYTES + 10];
    readCount = 0;
    while (fread(readBuffer, 1, MESSBYTES, plainFile)) {
        readCount++;
        if (readCount == lastCount) {
            process(readBuffer, key);
        } else {
            fwrite(writeBuffer, 1, MESSBYTES, cipherFile);
        }
    }

    fclose(plainFile);
    fclose(cipherFile);
}

void decrypt(const char *keyFileName, const char *cipherFileName,
             const char *plainFileName) {
    FILE *keyFile = fopen(keyFileName, "rb");
    FILE *cipherFile = fopen(cipherFileName, "rb");
    FILE *plainFile = fopen(plainFileName, "wb");
    if (keyFile == NULL || plainFile == NULL || cipherFile == NULL) {
        fprintf(stderr, "File open error\n");
        exit(1);
    }

    unsigned char key[KEYBYTES + 5];
    int readCount = 0;
    readCount = fread(key, 1, KEYBYTES, keyFile);
    if (readCount != KEYBYTES) {
        fprintf(stderr, "Key is too short\n");
        exit(1);
    }

    fclose(keyFile);
    fclose(plainFile);
    fclose(cipherFile);
}

void print_char_as_binary(unsigned char input) {
    int i;
    for (i = 0; i < 8; i++) {
        unsigned char shift_byte = 0x01 << (7 - i);
        if (shift_byte & input) {
            printf("1");
        } else {
            printf("0");
        }
    }
}

void print_Key(Key Key) {
    int i;
    printf("K: \n");
    for (i = 0; i < 8; i++) {
        printf("%02X : ", Key.k[i] & 0xff);
        print_char_as_binary(Key.k[i]);
        printf("\n");
    }
    printf("\nC: \n");

    for (i = 0; i < 4; i++) {
        printf("%02x : ", Key.c[i] & 0xff);
        print_char_as_binary(Key.c[i]);
        printf("\n");
    }
    printf("\nD: \n");

    for (i = 0; i < 4; i++) {
        printf("%02X : ", Key.d[i] & 0xff);
        print_char_as_binary(Key.d[i]);
        printf("\n");
    }
    printf("\n");
}

int main() {
    unsigned char key[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // int table[]={8,7,6,5,4,3,2,1};
    // unsigned char buffer[]={0};
    // permute(key,table,8,buffer);
    // printf("%2x\n",buffer[0]&0xff);
    Key *keys = generateSubKey(key);
    for (int i = 0; i < 17; i++) {
        printf("%d: \n", i);
        print_Key(keys[i]);
    }
    free(keys);
}