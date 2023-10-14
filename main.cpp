#include "program.h"

BYTE* sha256_test(BYTE* text, int length)
{
	BYTE* buf = new BYTE[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, text, length);
	sha256_final(&ctx, buf);
	return buf;
}

string hashPassword(const string& password)
{
      BYTE* myByte = (BYTE*)password.c_str();
      string hashedPassword((char*)sha256_test(myByte, password.length()));

      return hashedPassword;
}

void encrypt()
{
	printf("file's name: ");
	string filename;
	cin >> filename;

	printf("password: ");
	string password;
	cin >> password;

	printf("repassword: ");
	string repassword;
	cin >> repassword;

	if (password != repassword) {
		printf("password not match\n");
		return;
	}

	WORD key_schedule[60];
	BYTE* key = sha256_test((BYTE*)password.c_str(), password.length());
	BYTE iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
	FILE* fp = fopen(filename.c_str(), "rb");
	
	if (fp == NULL) 
	{
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
	string filename;
	cin >> filename;

	printf("password: ");
	string password;
	cin >> password;
      
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

	size_t pos = filename.find(".enc");
	if (pos == string::npos || pos != filename.length() - 4) {
		printf("Invalid file format\n");
		return;
	}

	// Modify the filename to ".dec" extension
	filename.replace(pos, 4, ".dec");
	fp = fopen((filename).c_str(), "wb");

	fwrite(buf, 1, size - paddingSize, fp);
	fclose(fp);
	delete[] buf;
	printf("decrypt success\n");
}

class DynamicPassword {
private:
      string storedPassword;
    
public:
      // Constructor:
      DynamicPassword() { this->storedPassword = ""; }

      DynamicPassword(const string& enteredPassword) {
           this->storedPassword = (enteredPassword);
      }

      bool validDynamicPassword(string enteredPassword) const
      {
            // Băm mật khẩu nhập vào và so sánh với mật khẩu được lưu trữ
            string hashedEnteredPassword = hashPassword(enteredPassword);

            if (hashedEnteredPassword == storedPassword) {
                  cout << "Password is correct. Continue running the program." << endl;
                  // Đây là nơi để tiếp tục thực hiện mã của bạn
                  return true;
            } else {
                  cout << "Incorrect password. Program terminated." << endl;
                  return false;
            }
      }

      bool isFileEmpty(const string& filename) {
            ifstream file(filename);

            // Kiểm tra xem tệp có mở thành công không
            if (!file.is_open()) {
                  cout << "Cannot open file: " << filename << endl;
                  return false;
            }

            // Kiểm tra xem tệp có rỗng không
            return file.peek() == ifstream::traits_type::eof();
      }

      string readDynamicPassFromFile(const string& filename) {
            ifstream file(filename);
            string content;
            
            if (file.is_open()) {
                  // Đọc nội dung từ tệp vào chuỗi content
                  content.assign((istreambuf_iterator<char>(file)),
                                    (istreambuf_iterator<char>()));

                  if (content == "")
                  {

                  }
                  this->storedPassword = hashPassword(content);

                  
                  file.close();
            } else {
                  cout << "Could not open file: " << filename << endl;
            }

            return content;
      }

      void writeToFile(const string& filename) {
            ofstream file(filename);

            if (file.is_open()) {
                  // Ghi nội dung đã chỉnh sửa vào tệp
                  file << this->storedPassword;
                  file.close();
            } else {
                  cout << "Could not open file for writing: " << filename << endl;
            }
      }

      void writeToFile(const string& filename, string content) {
            ofstream file(filename);

            if (file.is_open()) {
                  // Ghi nội dung đã chỉnh sửa vào tệp
                  file << content;
                  file.close();
            } else {
                  cout << "Could not open file for writing: " << filename << endl;
            }
      }

      void loadingDynamicPass() 
      {
            this->readDynamicPassFromFile("dyP.txt");
      }

      void resetDynamicPassword()
      {
            string currentPassword;
            cout << "Enter the current dynamic password: ";    
            cin >> currentPassword;

            while (true) 
            {
                  if (this->validDynamicPassword(currentPassword))
                  {
                        string newPassword;
                        cout << "Enter the new dynamic password: ";
                        cin >> newPassword;

                        string reNewPassword;
                        cout << "Re-enter the new dynamic password: ";
                        cin >> reNewPassword;

                        if (newPassword != reNewPassword)
                        {
                              cout << "password not match\n";
                              cout << "Re-enter the new dynamic password again: ";
                              cin >> reNewPassword;
                        }

                        this->storedPassword = newPassword;
                        this->writeToFile("dyP.txt");

                        cout << "Reset password successfully!\n";
                        return;
                  } else {
                        cout << "Please enter the current dynamic password again: ";    
                        cin >> currentPassword;
                  }
            }
      }
};

int main()
{
      DynamicPassword dynamicPassword;
      string dyPFile = "dyP.txt";
      string enteredPassword;

      if (dynamicPassword.isFileEmpty(dyPFile)) 
      {           
            cout << "Register the dynamic password: ";
            cin >> enteredPassword;

            dynamicPassword.writeToFile(dyPFile, enteredPassword);       
      } else {
            dynamicPassword.loadingDynamicPass();

            cout << "Enter the dynamic password: ";
            cin >> enteredPassword;

            while (!dynamicPassword.validDynamicPassword(enteredPassword))
            {
                  cout << "Please re-enter password..." << endl;
                  cout << "Enter the dynamic password again: ";
                  cin >> enteredPassword;
            }
      }

	srand(time(NULL));
	while (true) {
		printf("1. encrypt\n");
		printf("2. decrypt\n");
            printf("3. reset dynamic password\n");

		printf("10. exit\n");
		printf("select: ");

		int select;
		cin >> select;

		switch (select) {
			case 1:
				encrypt();
				break;
			case 2:
				decrypt();
				break;
                  case 3:
                        dynamicPassword.resetDynamicPassword();
                        return 0;
                  
			case 10:
				return 0;
			default:
				printf("select error\n");
				break;
		}
	}
	return 0;
}