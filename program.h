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

// void obfuscated(const char* fileName) {
//       // Open the file
//       ifstream inputFile(fileName);
//       if (!inputFile.is_open()) {
//             cout << "Error opening file: " << fileName << endl;
//             return;
//       }

//       // Read the content of the file
//       string content((istreambuf_iterator<char>(inputFile)),
//                         istreambuf_iterator<char>());

//       // Obfuscate the content by shifting each character
//       for (char& c : content) {
//             c += 1;
//       }

//       // Print the obfuscated content
//       cout << "Obfuscated Content:\n" << content << endl;
// }