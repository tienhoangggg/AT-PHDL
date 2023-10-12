#ifndef PROGRAM_H   
#define PROGRAM_H

#include <iostream>
#include <string.h>
#include <memory.h>
#include "sha256/sha256.cpp"
#include "aes/aes.cpp"
#include <fstream>

using namespace std;

BYTE* sha256_test(BYTE* text, int length);
void encrypt();
void decrypt();

#endif // PROGRAM_H