#pragma once
#include <Windows.h>
#include <Wincrypt.h>
#include <ctime>
#include <string>
#include <windows.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
using namespace std;

void make_hash(const char * data, BYTE ** hash, long * len);
int gen_key_pair(BYTE ** strPublicKey, int *lenPub, BYTE ** strPrivateKey, int *lenPri, int len);
int encrypt_private_key(string passPhrase, BYTE ** privateKey, int len);
int decrypt_private_key(string passPhrase, BYTE ** privateKey, int * len);

int encrypt_file(wstring, BYTE *,int len,int algo);
int decrypt_file(wstring, BYTE *,int len);

int sign_file(wstring, BYTE *, int len);
int check_sign(wstring,wstring, BYTE *, int len);



int ByteToBase64(const BYTE * pSrc, int nLenSrc, string & res, int nLenDst);
int Base64ToByte(string pSrc, int nLenSrc, BYTE ** pDst, int nLenDst);
