#include <cstring>
#include <iostream>
#include <string>
using namespace std;

unsigned char bssHashXorTable[33] = {0x1A, 0x0C, 0x2D, 0x1C, 0x0F, 0x0D, 0x3E, 0x01, 0x32,
                                     0x88, 0xD3, 0x23, 0x87, 0xAD, 0xEA, 0x82, 0x99, 0xAB,
                                     0x01, 0x32, 0x87, 0x98, 0x34, 0x83, 0x82, 0x32, 0x13,
                                     0x15, 0x16, 0x82, 0x19, 0x29, 0x0};
void printHex(const char* const p) {
    size_t len = strlen(p);
    int idx = 0;
    char hexStr[8];
    char outStr[128];
    memset(outStr, 0, sizeof(outStr));
    while (idx < len) {
        sprintf(hexStr, "%02X", (unsigned char)p[idx]);  // Hash Step-2: Xor
        strcat(outStr, hexStr);
        strcat(outStr, ", ");
        idx++;
    }
    printf("[hex] %s len= %u\n", outStr, len);
}

const char* hexstr2bytes(const char* inStr, unsigned int halfInStrLen, char* tmpStr);
string XorFunc(const char* instr) {
    unsigned char* pXorTable = bssHashXorTable;
    char hexStr[8];

    char tmpStr[32];
    memset(tmpStr, 0, sizeof(tmpStr));
    // char* outStr = (char*)malloc(128);  //char[128];
    char outStr[128];
    memset(outStr, 0, sizeof(outStr));

    size_t instr_len = strlen(instr);
    hexstr2bytes(instr, instr_len >> 1, tmpStr);
    // printHex(tmpStr);  // DEBUG
    size_t tmpStrLen = strlen(tmpStr);
    signed int idx = 0;
    while (idx < tmpStrLen) {
        int B1 = (unsigned char)pXorTable[idx];
        int B2 = (unsigned char)tmpStr[idx++];
        sprintf(hexStr, "%02X", B2 ^ B1);  // Hash Step-2: Xor
        strcat(outStr, hexStr);
    }
    // printf("[debug]idx= %d, outStr= %s, outStrLen= %u, tmpStrLen= %u\n", idx, outStr,
    //        strlen(outStr), tmpStrLen);
    string retStr(outStr);
    return retStr;
}


// 把传入的由数字组成的可见字符串 转换为 相应数字组成的可能不可见的字符串
const char* hexstr2bytes(const char* inStr, unsigned int halfInStrLen, char* tmpStr) {
    unsigned int max = halfInStrLen >> 1;  // 最后会变成instr长度的1/4
    const char* in_str = inStr;
    for (int i = 0; i != max; ++i) {
        int B2 = (unsigned char)in_str[2 * i + 1];
        if (isalpha(B2)) {  // 是字母则转大写
            B2 = toupper(B2);
        }
        unsigned char B22 = (unsigned char)(B2 - '0');  // 转成数字
        if (B22 > 9) {  // 如果原本是个字母，则转换为数字 比如'A'=65; 65-55=10
            B22 = B2 - 55;
        }
        // 上下两小段逻辑类似
        int B1 = (unsigned char)in_str[2 * i];
        if (isalpha(B1)) {
            B1 = toupper(B1);
        }
        unsigned char B11 = (unsigned char)(B1 - '0');
        if (B11 > 9) {
            B11 = B1 - 55;
        }
        //
        tmpStr[i] = B22 | (16 * B11);
    }
    return inStr;
}

string bytes2hexstr(char* inStr) {
    char outStr[128];
    char tempStr[8];
    memset(outStr, 0, sizeof(outStr));
    memset(tempStr, 0, sizeof(tempStr));
    for (int i = 0; i < strlen(inStr); i++) {
        unsigned num = (unsigned char)inStr[i];
        unsigned firstDigit = num / 16;
        unsigned secondDigit = num % 16;
        if (firstDigit <= 9) {
            tempStr[0] = firstDigit + '0';
        } else {
            tempStr[0] = firstDigit + 55;
        }
        strcat(outStr, tempStr);

        if (secondDigit <= 9) {
            tempStr[0] = secondDigit + '0';
        } else {
            tempStr[0] = secondDigit + 55;
        }
        strcat(outStr, tempStr);
    }
    return string(outStr);
}
string REXorFunc(const char* instr) {
    unsigned char* pXorTable = bssHashXorTable;
    char outStr[128];
    memset(outStr, 0, sizeof(outStr));
    string ret;
    size_t LEN = strlen(instr);
    for (int i = 0; i < LEN; i += 2) {
        char temp[3] = {instr[i], instr[i + 1], 0x0};
        int num = strtol(temp, NULL, 16);
        temp[0] = (char)num;
        temp[1] = '\0';
        strcat(outStr, temp);
    }
    for (int i = 0; i < strlen(outStr); i++) {
        outStr[i] = outStr[i] ^ pXorTable[i];
    }
    ret = bytes2hexstr(outStr);
    return ret;
}

int main() {
    const char* in_s = "480E1C995149230BC5DF87EEB25E2F8A4B01B9F307391E35";
    printf("[input] %s, len= %u\n", in_s, strlen(in_s));

    string ret = XorFunc(in_s);
    printf("after xor: %s, len= %u\n", ret.c_str(), ret.length());
    // printHex(ret.c_str());

    // 这个字符串是最开始输入为16个0时，最后strcmp时的字符串
    unsigned char Str16x0[33] = {0x35, 0x32, 0x30, 0x32, 0x33, 0x31, 0x38, 0x35, 0x35,
                                 0x45, 0x34, 0x34, 0x31, 0x44, 0x30, 0x41, 0x46, 0x37,
                                 0x35, 0x37, 0x35, 0x34, 0x43, 0x44, 0x0};
    for (int i = 0; i < ret.length(); i++) {
        if (ret.at(i) != Str16x0[i]) {
            printf("[NOT equal]%c!=%c, %x!=%x\n", ret.at(i), Str16x0[i], ret.at(i), Str16x0[i]);
        }
    }
    ret = REXorFunc(ret.c_str());
    printf("[REXor] %s, len= %u\n", ret.c_str(), ret.length());
    printf("TEST END, lhs reverse:\n\n");


    string lhs("16D71D14B3F9B6519A28AB54");  // 最后用于strcmp(lhs, rhs)的字符串lhs
    printf("[lhs] %s, len= %u\n", lhs.c_str(), lhs.length());
    ret = REXorFunc(lhs.c_str());
    printf("[REXor] %s, len= %u\n", ret.c_str(), ret.length());

    string lhs_ori = "0CDB3008BCF48850A8A07877000000000000000000000000";  // 16+16+16 48 B
    printf("[lhs_ori] %s, len= %u\n", lhs_ori.c_str(), lhs_ori.length());
    ret = XorFunc(lhs_ori.c_str());
    printf("[lhs_ori] after xor: %s, len= %u\n", ret.c_str(), ret.length());
    printHex(ret.c_str());
}
