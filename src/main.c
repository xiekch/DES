#include "DES.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "please input filename to be processed\n");
        fprintf(stderr, "please input key filename\n");
        fprintf(stderr, "please input filename to be output to\n");
        fprintf(stderr, "please input mode. 1: encrypt; 0: decrypt\n");
    }
    char *inputFilename = argv[1], *keyFilename = argv[2],
         *outputFilename = argv[3];
    int mode = atoi(argv[4]);
    if (mode == 1) {
        encryptData(keyFilename, inputFilename, outputFilename);
    } else if (mode == 0){
        decryptData(keyFilename, inputFilename, outputFilename);
    }

    return 0;
}