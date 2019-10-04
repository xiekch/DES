#include "DES.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEYBYTES 8
#define MESSBYTES 8
#define KEYLEN 64
#define MESSLEN 64

typedef struct Key {
    unsigned char k[8];
    unsigned char c[4];
    unsigned char d[4];
} Key;

void printBytes(char *data, int len);
void printKey(Key Key);

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

const int feistelP[] = {16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23,
                        26, 5, 18, 31, 10, 2,  8,  24, 14, 32, 27,
                        3,  9, 19, 13, 30, 6,  22, 11, 4,  25};

const int W[] = {33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
                 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
                 59, 60, 61, 62, 63, 64, 1,  2,  3,  4,  5,  6,  7,
                 8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
                 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

const int eight2six64[] = {
    1,  2,  3,  4,  5,  6,  1, 1, 7,  8,  9,  10, 11, 12, 1, 1,
    13, 14, 15, 16, 17, 18, 1, 1, 19, 20, 21, 22, 23, 24, 1, 1,
    25, 26, 27, 28, 29, 30, 1, 1, 31, 32, 33, 34, 35, 36, 1, 1,
    37, 38, 39, 40, 41, 42, 1, 1, 43, 44, 45, 46, 47, 48, 1, 1,
};

const int four2eight32[] = {5,  6,  7,  8,  13, 14, 15, 16, 21, 22, 23,
                            24, 29, 30, 31, 32, 37, 38, 39, 40, 45, 46,
                            47, 48, 53, 54, 55, 56, 61, 62, 63, 64};

void bitMapping(unsigned char *data, const int *permTable, int dataLen,
             int resultLen, unsigned char *result) {
    unsigned char src[20] = {0};
    memcpy(src, data, dataLen / 8 + (dataLen % 8 ? 1 : 0));
    memset(result, 0, resultLen / 8 + (resultLen % 8 ? 1 : 0));

    unsigned char bit = 0;
    for (int i = 0; i < resultLen; i++) {
        bit = src[(permTable[i] - 1) / 8] & (0x80u >> ((permTable[i] - 1) % 8));
        if (bit)
            result[i / 8] |= 0x80u >> (i % 8);
    }
}

// bit shift, avoid hardware-related shift (big end/little end)
// shiftBits > 0 : left shift
void cycleShift(unsigned char *data, int shiftBits, int len,
                unsigned char *result) {
    unsigned char src[20] = {0};
    memcpy(src, data, len / 8 + (len % 8 ? 1 : 0));
    memset(result, 0, len / 8 + (len % 8 ? 1 : 0));

    unsigned char temp = (src[0] & (0xff << (8 - shiftBits)));

    unsigned char bit = 0;
    for (int i = 0; i < len; i++) {
        bit = src[(i + shiftBits) / 8] & (0x80u >> ((i + shiftBits) % 8));
        if (bit)
            result[i / 8] |= 0x80u >> (i % 8);
    }
    result[(len - 1) / 8] |= temp >> ((len % 8) - shiftBits);
}

Key *generateSubKey(unsigned char *key, Key *keys) {
    memset(keys, 0, sizeof(Key) * 17);
    bitMapping(key, keyPC1, 64, 28, keys[0].c);
    bitMapping(key, keyPC1 + 28, 64, 28, keys[0].d);
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

        memcpy(buffer, keys[i].c, 4);
        unsigned char temp = (keys[i].d[0] & (0xf0));
        cycleShift(keys[i].d, 4, 28, buffer + 4);
        buffer[3] |= temp >> 4;
        bitMapping(buffer, keyPC2, 56, 48, keys[i].k);
    }

    return keys;
}

void feistel(unsigned char *data, unsigned char *key, unsigned char *result) {
    unsigned char buffer[20] = {0};

    bitMapping(data, messageE, 32, 48, buffer);

    for (int i = 0; i < 6; i++) {
        buffer[i] ^= key[i];
    }

    unsigned char row, column, group[8] = {0};
    bitMapping(buffer, eight2six64, 64, 64, buffer);
    for (int i = 0; i < 8; i++) {
        row = 0;
        row |= ((buffer[i] & 0x80) >> 6);
        row |= ((buffer[i] & 0x04) >> 2);

        column = 0;
        column |= ((buffer[i] & 0x78) >> 3);

        group[i] = (unsigned char)(SBoxes[i][row * 16 + column]);
    }

    bitMapping(group, four2eight32, 64, 32, result);
    bitMapping(result, feistelP, 32, 32, result);
}

void process(unsigned char *data, Key *keys, unsigned char *result,
             int encrypt) {
    printf("data");
    printBytes(data, 8);
    // printf("key");printBytes(key,8);
    bitMapping(data, IP, 64, 64, result);

    int j;
    unsigned char buffer[20];
    for (int i = 1; i <= 16; i++) {
        if (encrypt) {
            j = i;
        } else {
            j = 16 - i + 1;
        }

        bitMapping(result, W, 64, 64, result);

        feistel(result, keys[j].k, buffer);
        for (int k = 0; k < 4; k++) {
            result[k + 4] ^= buffer[k];
        }
    }

    bitMapping(result, W, 64, 64, result);
    bitMapping(result, IPReverse, 64, 64, result);
    printf("output");
    printBytes(result, 8);
}

void DES(const char *inputFileName, const char *keyFileName,
         const char *outputFileName, int encrypt) {
    FILE *keyFile = fopen(keyFileName, "rb");
    FILE *inputFile = fopen(inputFileName, "rb");
    FILE *outputFile = fopen(outputFileName, "wb");
    if (keyFile == NULL || inputFile == NULL || outputFile == NULL) {
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
    Key keys[17] = {0};
    generateSubKey(key, keys);

    fseek(inputFile, 0, SEEK_END);
    int file_size = ftell(inputFile);
    fseek(inputFile, 0, SEEK_SET);
    int lastCount = file_size / 8 + ((file_size % 8) ? 1 : 0);
    unsigned char readBuffer[MESSBYTES + 10];
    unsigned char writeBuffer[MESSBYTES + 10];
    readCount = 0;
    while (fread(readBuffer, 1, MESSBYTES, inputFile)) {
        memset(writeBuffer, 0, sizeof(writeBuffer));
        readCount++;
        if (readCount == lastCount) {
            unsigned char padding = 8 - file_size % 8;
            if (encrypt) {
                if (padding < 8) {
                    memset(readBuffer + (8 - padding), padding, padding);
                }
                process(readBuffer, keys, writeBuffer, encrypt);
                fwrite(writeBuffer, 1, MESSBYTES, outputFile);

                if (padding == 8) {
                    memset(readBuffer, padding, padding);
                    process(readBuffer, keys, writeBuffer, encrypt);
                    fwrite(writeBuffer, 1, MESSBYTES, outputFile);
                }
            } else {
                process(readBuffer, keys, writeBuffer, encrypt);
                padding = writeBuffer[7];
                if (padding < 8) {
                    fwrite(writeBuffer, 1, MESSBYTES - writeBuffer[7],
                           outputFile);
                }
            }
        } else {
            process(readBuffer, keys, writeBuffer, encrypt);
            fwrite(writeBuffer, 1, MESSBYTES, outputFile);
        }
    }

    fclose(inputFile);
    fclose(outputFile);
}

void encryptData(const char *keyFileName, const char *plainFileName,
                 const char *cipherFileName) {
    printf("encrypt\n");
    DES(plainFileName, keyFileName, cipherFileName, 1);
}

void decryptData(const char *keyFileName, const char *cipherFileName,
                 const char *plainFileName) {
    printf("decrypt\n");
    DES(cipherFileName, keyFileName, plainFileName, 0);
}

void printBytes(char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X : ", data[i] & 0xff);
        for (int j = 0; j < 8; j++) {
            unsigned char byte = 0x01 << (7 - j);
            if (byte & data[i]) {
                printf("1");
            } else {
                printf("0");
            }
        }
        printf("\n");
    }
    printf("\n");
}

void generateKey(const char *keyFileName) {
    FILE *keyFile = fopen(keyFileName, "wb");
    char key[8];
    for (int i = 0; i < 8; i++) {
        key[i] = (char)(rand() % 0xff);
    }
    fwrite(key, 1, KEYBYTES, keyFile);
    fclose(keyFile);
}
