#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
//#include <conio.h>
#include <string.h>
#include<unistd.h>
#include <sys/types.h>		//定义了一些常用数据类型，比如size_t
#include <fcntl.h>			//定义了open、creat等函数，以及表示文件权限的宏定义
#include <unistd.h>			//定义了read、write、close、lseek等函数
#include <errno.h>			//与全局变量errno相关的定义
#include <sys/ioctl.h>		//定义了ioctl函数 

#pragma warning(disable:4996)

//S盒
const unsigned char s[16][16] =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
//逆S盒
const unsigned char inv_s[16][16] =
{
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
//轮常数
const unsigned char Rcon[11][4] =
{
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00,
    0x1b, 0x00, 0x00, 0x00,
    0x36, 0x00, 0x00, 0x00
};

void ByteToBits(unsigned char ch, unsigned char bit[]);//字节转换为二进制数
void SubBytes(unsigned char status[][4], unsigned char bit[]);//S盒变换
void Inv_SubBytes(unsigned char status[][4], unsigned char bit[]);//逆S盒变换
void ShiftRows(unsigned char status[][4]);//行移位
void Inv_ShiftRows(unsigned char status[][4]);//逆行移位
unsigned char xTime(unsigned char c);//x乘法
void MixColumns(unsigned char status[][4]);//列混合
void Inv_MixColumns(unsigned char status[][4]);//逆列混合
void RotWord(unsigned char c[], unsigned char temp[]);//循环左移一位
void SubWord(unsigned char temp[], unsigned char bit[]);//小S盒变换
void KeyExpansion(unsigned char k[][4], unsigned char key[][4], unsigned char bit[]);//密钥扩展算法
void RoundKeyChoice(unsigned char key[][4], unsigned char RoundKey[][4], int cnt); //加密时从扩展密钥中选择轮密钥
void Inv_RoundKeyChoice(unsigned char key[][4], unsigned char RoundKey[][4], int cnt); //解密时从扩展密钥中选择轮密钥
void AddRoundKey(unsigned char RoundKey[][4], unsigned char status[][4]);//与扩展密钥进行异或运算(加密)
void Inv_AddRoundKey(unsigned char RoundKey[][4], unsigned char status[][4]);//与扩展密钥进行异或运算(解密)
void Encrypt(unsigned char key[][4], unsigned char RoundKey[][4], unsigned char bit[], unsigned char status[][4]);//加密
void Decrypt(unsigned char key[][4], unsigned char RoundKey[][4], unsigned char bit[], unsigned char status[][4]);//解密
void Print(unsigned char status[][4]);//打印当前状态
int Select();//菜单选项

void ByteToBits(unsigned char ch, unsigned char bit[])
{
    for (int i = 0; i < 8; i++) {
        bit[i] = (ch >> i) & 1;
    }
}
void SubBytes(unsigned char status[][4], unsigned char bit[])
{
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            ByteToBits(status[i][j], bit);
            status[i][j] = s[(bit[7] * 8 + bit[6] * 4 + bit[5] * 2 + bit[4])][(bit[3] * 8 + bit[2] * 4 + bit[1] * 2 + bit[0])];
        }
    }
    //printf("SubBytes: ");
    Print(status);
}
void Inv_SubBytes(unsigned char status[][4], unsigned char bit[])
{
    int i, j;
    for (i = 0; i < 4; i++){
        for (j = 0; j < 4; j++) {
            ByteToBits(status[i][j], bit);
            status[i][j] = inv_s[(bit[7] * 8 + bit[6] * 4 + bit[5] * 2 + bit[4])][(bit[3] * 8 + bit[2] * 4 + bit[1] * 2 + bit[0])];
        }
    }
    //printf("Inv_SubBytes: ");
    Print(status);
}
void ShiftRows(unsigned char status[][4])
{
    unsigned char temp1 = status[1][0];
    unsigned char temp2 = status[2][0];
    unsigned char temp3 = status[2][1];
    unsigned char temp4 = status[3][0];
    unsigned char temp5 = status[3][1];
    unsigned char temp6 = status[3][2];
    for (int i = 0; i < 3; i++) {
        status[1][i] = status[1][(i + 1)];//对第一行变换
    }
    status[1][3] = temp1;
    for (int i = 0; i < 2; i++) {
        status[2][i] = status[2][(i + 2)];//对第二行变换
    }
    status[2][2] = temp2;
    status[2][3] = temp3;
    status[3][0] = status[3][3];
    status[3][1] = temp4;
    status[3][2] = temp5;
    status[3][3] = temp6;
    //printf("ShiftRows: ");
    Print(status);
}
void Inv_ShiftRows(unsigned char status[][4])
{
    int i;
    unsigned char temp1 = status[1][3];
    unsigned char temp2 = status[2][2];
    unsigned char temp3 = status[2][3];
    unsigned char temp4 = status[3][1];
    for (i = 3; i > 0; i--){
        status[1][i] = status[1][i - 1];
    }
    status[1][0] = temp1;
    for (i = 3; i > 1; i--) {
        status[2][i] = status[2][i - 2];
    }
    status[2][0] = temp2;
    status[2][1] = temp3;
    for (i = 1; i < 4; i++) {
        status[3][i] = status[3][(i + 1) % 4];
    }
    status[3][0] = temp4;
    //printf("Inv_ShiftRows: ");
    Print(status);
}
unsigned char xTime(unsigned char c)
{
    unsigned char temp;
    temp = c << 1;
    if (c & 0x80) {
        temp ^= 0x1b;
    }
    return temp;
}
void MixColumns(unsigned char status[][4])
{
    int i, j;
    unsigned char temp[4][4];
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++){
            temp[i][j] = xTime(status[i % 4][j]) //0x02乘法
            ^ (status[(i + 1) % 4][j] ^ xTime(status[(i + 1) % 4][j])) //0x03乘法
            ^ status[(i + 2) % 4][j]  //0x01乘法
            ^ status[(i + 3) % 4][j]; //0x01乘法
        }
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            status[i][j] = temp[i][j];
        }
    } 
    //printf("MixColumns: ");
    Print(status);
}
void Inv_MixColumns(unsigned char status[][4])
{
    int i, j;
    unsigned char temp[4][4];
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++) {
            temp[i][j] = (xTime(xTime(xTime(status[i % 4][j]))) ^ xTime(xTime(status[i % 4][j])) ^ xTime(status[i % 4][j])) //0x0E乘法
            ^ (xTime(xTime(xTime(status[(i + 1) % 4][j]))) ^ xTime(status[(i + 1) % 4][j]) ^ status[(i + 1) % 4][j]) //0x0B乘法
            ^ (xTime(xTime(xTime(status[(i + 2) % 4][j]))) ^ xTime(xTime(status[(i + 2) % 4][j])) ^ status[(i + 2) % 4][j]) //0x0D乘法
            ^ (xTime(xTime(xTime(status[(i + 3) % 4][j]))) ^ status[(i + 3) % 4][j]); //0x09乘法
        }
    }
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            status[i][j] = temp[i][j];
        }
    }
}
void RotWord(unsigned char c[], unsigned char temp[])
{
    for (int i = 1; i < 4; i++) {
        temp[i - 1] = c[i];
    }
    temp[3] = c[0];
}
void SubWord(unsigned char temp[], unsigned char bit[])
{
    for (int i = 0; i < 4; i++) {
        ByteToBits(temp[i], bit);
        temp[i] = s[(bit[7] * 8 + bit[6] * 4 + bit[5] * 2 + bit[4])][(bit[3] * 8 + bit[2] * 4 + bit[1] * 2 + bit[0])];
    }
}
void KeyExpansion(unsigned char k[][4], unsigned char key[][4], unsigned char bit[])
{
    int i, j;
    unsigned char temp[4];
    for (i = 0; i < 44; i++) {
        for (j = 0; j < 4; j++) {
            if (i < 4)
                key[i][j] = k [i][j];
            else if ((i != 0) && (i % 4 == 0)) {
                RotWord(key[i - 1], temp);
                SubWord(temp, bit);
                key[i][j] = key[i - 4][j] ^ temp[j] ^ Rcon[i / 4][j];
            }
            else  
                key[i][j] = key[i - 1][j] ^ key[i - 4][j];
        }
    }
}
void RoundKeyChoice(unsigned char key[][4], unsigned char RoundKey[][4], int cnt)
{
    //printf("轮密钥：");
    int cnt1 = 4 * cnt;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            RoundKey[i][j] = key[cnt1][j];
            //printf("%02x", RoundKey[i][j]);
        }
        cnt1++;
    }
    //printf("\n");
}
void Inv_RoundKeyChoice(unsigned char key[][4], unsigned char RoundKey[][4], int cnt)
{
    int cnt1 = 4 * cnt;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            RoundKey[j][i] = key[cnt1][j];
        }
        cnt1++;
    }
    Inv_MixColumns(RoundKey);
    //printf("轮密钥：");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            //printf("%02x", RoundKey[j][i]);
        }
        cnt1++;
    }
    //printf("\n");
}
void AddRoundKey(unsigned char RoundKey[][4], unsigned char status[][4])
{
    int i, j;
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++) {
            status[i][j] = status[i][j] ^ RoundKey[j][i];
        }
    }
    //printf("AddRoundKey: ");
    Print(status);
}
void Inv_AddRoundKey(unsigned char RoundKey[][4], unsigned char status[][4])
{
    int i, j;
    for (j = 0; j < 4; j++) {
        for (i = 0; i < 4; i++) {
            status[i][j] = status[i][j] ^ RoundKey[i][j];
        }
    }
    //printf("AddRoundKey: ");
    Print(status);
}
void Encrypt(unsigned char key[][4], unsigned char RoundKey[][4], unsigned char bit[], unsigned char status[][4])
{
    //printf("\n明文：");
    Print(status);
    RoundKeyChoice(key, RoundKey, 0);
    AddRoundKey(RoundKey, status);
    for (int nr = 1; nr <= 9; nr++) {
        //printf("\nN=%d \n", nr);
        SubBytes(status, bit);
        ShiftRows(status);
        MixColumns(status);
        RoundKeyChoice(key, RoundKey, nr);
        AddRoundKey(RoundKey, status);
    }//前9轮加密
    //printf("\nN=10\n");
    SubBytes(status, bit);
    ShiftRows(status);
    RoundKeyChoice(key, RoundKey, 10);
    AddRoundKey(RoundKey, status);
   // printf("\n\n最终得到密文：");
    Print(status);
}
void Decrypt(unsigned char key[][4], unsigned char RoundKey[][4], unsigned char bit[], unsigned char status[][4])
{
    //printf("\n密文：");
    Print(status);
    RoundKeyChoice(key, RoundKey, 10);
    AddRoundKey(RoundKey, status);
    for (int nr = 9; nr >= 1; nr--) {
        //printf("\nN=%d \n", nr+1);
        Inv_SubBytes(status, bit);
        Inv_ShiftRows(status);
        Inv_MixColumns(status);
        //printf("Inv_MixColumns: ");
        Print(status);
        Inv_RoundKeyChoice(key, RoundKey, nr);
        Inv_AddRoundKey(RoundKey, status);
     }//9轮解密 
    //printf("\nN=1\n");
    Inv_SubBytes(status, bit);
    Inv_ShiftRows(status);
    RoundKeyChoice(key, RoundKey, 0);
    AddRoundKey(RoundKey, status);
    //printf("\n\n最终得到明文：");
    Print(status);
}
void Print(unsigned char status[][4])
{
    int i, j;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            //printf("%02x", status[j][i]);
        }
    }
    //printf("\n");
}
int Select()
{
    int x;
    printf("\n*****菜单*****\n");
    printf("1->加密\n");
    printf("2->解密\n");
    printf("88->退出\n");
    printf("**************\n");
    printf("请输入您想进行的操作：");
    scanf("%d", &x);
    return x;
}

int main()
{
    int s;//选项
    unsigned char status[4][4] = { 0x00, 0x01, 0xda, 0x86,
                                   0x01, 0xa1, 0x78, 0x15,
                                   0x00, 0x98, 0x17, 0x35,
                                   0x01, 0xaf, 0x34, 0x66 };//明文
    unsigned char k[4][4] = { 0x00, 0x01, 0x20, 0x01,
                              0x71, 0x01, 0x98, 0xae,
                              0xda, 0x79, 0x17, 0x14,
                              0x60, 0x15, 0x35, 0x94 };//初始密钥
    unsigned char key[44][4] = { 0x00 };//由初始密钥得到的扩展密钥
    unsigned char RoundKey[4][4] = { 0x00 };
    unsigned char bit[8] = { 0x00 };//处理单位：字节
    //KeyExpansion(k, key, bit);
    
    // while (1)
    // {
    //     s = Select();
    //     if (s == 88)break;
    //     switch (s)
    //     {
    //     case 1:
    //     {
    //         Encrypt(key,RoundKey,bit,status);
    //         break;
    //     }
    //     case 2:
    //     {
    //         Decrypt(key,RoundKey,bit,status);
    //         break;
    //     }
    //     default:
    //         //printf("数据输入有误，请重新输入！");
    //         break;
    //     }
    // }
    // for(int i=0;i<10;i++){
    //     Encrypt(key,RoundKey,bit,status);
    //     Decrypt(key,RoundKey,bit,status);
    // }
    int fd = -1;
    int res = 0;
    // char filename[]  = "/home/whisper/Documents/measure/sen.txt";
    // char filename1[]  = "/home/whisper/Documents/measure/sen1.txt";
    char filename2[]  = "/home/spike/workspace/project1/measure/sen2.txt";
    char write_dat[] = "Hello World!";
    // char read_buf[128] = {0};

    fd = open(filename2, O_RDWR | O_CREAT, 0664);
    if(fd < 0){
        printf("%s file open fail,errno = %d.\r\n", filename2, errno);
        return -1;
    }
    res = write(fd, write_dat, sizeof(write_dat));
    if(res < 0){
        printf("write dat fail,errno = %d.\r\n", errno);
        return -1;
    }
    else{
        printf("write %d bytes:%s\r\n", res, write_dat);
    }
    close(fd);

    // fd = open(filename1, O_RDONLY);
    // if(fd < 0){
    //     printf("%s file open fail,errno = %d.\r\n", filename1, errno);
    //     return -1;
    // }
    // res = read(fd, read_buf, sizeof(read_buf));
    // if(res < 0){
    //     printf("read dat fail,errno = %d.\r\n", errno);
    //     return -1;
    // }
    // else{
    //     printf("read %d bytes:%s\r\n", res, read_buf);
    // }
    // close(fd);

    // char *argv[ ]={"ls", "-al", "/etc/passwd", NULL};   
	// char *envp[ ]={"PATH=/bin", NULL};
	// execve("/bin/ls", argv, envp);
    return 0;
}
