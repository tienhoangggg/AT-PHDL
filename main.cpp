#include <iostream>
#include <memory.h>
#include <string.h>
#include "sha256.cpp"
#include "aes.cpp"
BYTE* sha256_test(BYTE* text, int length)
{
	BYTE* buf = new BYTE[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, text, length);
	sha256_final(&ctx, buf);
	return buf;
}

void encrypt()
{
	printf("file's name: ");
	std::string filename;
	std::cin >> filename;
	printf("password: ");
	std::string password;
	std::cin >> password;
	printf("repassword: ");
	std::string repassword;
	std::cin >> repassword;
	if (password != repassword) {
		printf("password not match\n");
		return;
	}
	WORD key_schedule[60];
	BYTE* key = sha256_test((BYTE*)password.c_str(), password.length());
	BYTE iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp == NULL) {
		printf("file open error\n");
		return;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	BYTE* buf = new BYTE[size];
	fread(buf, 1, size, fp);
	fclose(fp);
	int randPadding = (rand()%100) * 32 + 1 + (32 - size%32 - 1);
	int paddingSize = randPadding + size;
	BYTE* padding = new BYTE[paddingSize];
	for (int i = 0; i < 32; i++) {
		padding[i] = rand()%256;
	}
	for (int i = 32; i < randPadding - 1; i++) {
		padding[i] = 0;
	}
	padding[randPadding - 1] = 1;
	for (int i = 0; i < size; i++) {
		padding[i + randPadding] = buf[i];
	}
	delete[] buf;
	buf = new BYTE[paddingSize];
	aes_key_setup(key, key_schedule, 256);
	aes_encrypt_cbc(padding, paddingSize, buf, key_schedule, 256, iv);
	delete[] padding;
	fp = fopen((filename + ".enc").c_str(), "wb");
	fwrite(buf, 1, paddingSize, fp);
	fclose(fp);
	delete[] buf;
	printf("encrypt success\n");
}

void decrypt()
{
	printf("file's name: ");
	std::string filename;
	std::cin >> filename;
	printf("password: ");
	std::string password;
	std::cin >> password;
	WORD key_schedule[60];
	BYTE* key = sha256_test((BYTE*)password.c_str(), password.length());
	BYTE iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp == NULL) {
		printf("file open error\n");
		return;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	BYTE* buf = new BYTE[size];
	fread(buf, 1, size, fp);
	fclose(fp);
	BYTE* padding = new BYTE[size];
	aes_key_setup(key, key_schedule, 256);
	aes_decrypt_cbc(buf, size, padding, key_schedule, 256, iv);
	delete[] buf;
	int paddingSize = 0;
	for (int i = 32; i < size; i++) {
		if (padding[i] == 1) {
			paddingSize = i + 1;
			break;
		}
	}
	buf = new BYTE[size - paddingSize];
	for (int i = paddingSize; i < size; i++) {
		buf[i - paddingSize] = padding[i];
	}
	delete[] padding;
	fp = fopen((filename + ".dec").c_str(), "wb");
	fwrite(buf, 1, size - paddingSize, fp);
	fclose(fp);
	delete[] buf;
	printf("decrypt success\n");
}

int main()
{
	srand(time(NULL));
	while (true) {
		printf("1. encrypt\n");
		printf("2. decrypt\n");
		printf("3. exit\n");
		printf("select: ");
		int select;
		std::cin >> select;
		switch (select) {
			case 1:
				encrypt();
				break;
			case 2:
				decrypt();
				break;
			case 3:
				return 0;
			default:
				printf("select error\n");
				break;
		}
	}
	return 0;
}