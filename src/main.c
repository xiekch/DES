#include "DES.h"

int main() {
    encryptData("des.key", "test.txt", "cipher.txt");
    decryptData("des.key", "cipher.txt", "plain.txt");

    return 0;
}