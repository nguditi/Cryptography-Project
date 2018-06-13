#include "Support.h"

void make_hash(const char * data, BYTE ** hash, long * len)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE *pbHash = NULL;
	DWORD dwHashLen;
	BYTE * pbBuffer = NULL;
	DWORD dwCount;
	DWORD i;
	unsigned long bufLen = 0;
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		return;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		return;
	}
	bufLen = strlen(data);
	pbBuffer = (BYTE*)malloc(bufLen + 1);
	memset(pbBuffer, 0, bufLen + 1);

	for (i = 0; i < bufLen; i++) {
		pbBuffer[i] = (BYTE)data[i];
	}
	if (!CryptHashData(hHash, pbBuffer, bufLen, 0)) {
		return;
	}
	dwCount = sizeof(DWORD);
	if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&dwHashLen, &dwCount, 0)) {
		return;
	}
	if ((pbHash = (unsigned char*)malloc(dwHashLen)) == NULL) {
		return;
	}
	memset(pbHash, 0, dwHashLen);

	if (!CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
		return;
	}
	*hash = pbHash;
	*len = dwHashLen;
	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);
}

int gen_key_pair(BYTE ** pbPublicKey, int * lenpub, BYTE ** pbPrivateKey, int * lenpri, int len)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwPublicKeyLen = 0;
	DWORD dwPrivateKeyLen = 0;
	//convert len to flag 0x????0000;

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
		{
			return 0;
		}
	}
	int flag = (len << 16);
	if (!CryptGenKey(hProv, CALG_RSA_KEYX, flag | CRYPT_EXPORTABLE, &hKey))
	{
		return 0;
	}
	// Get public key size
	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen))
	{
		return 0;
	}
	if (!(*pbPublicKey = (BYTE*)malloc(dwPublicKeyLen)))
	{
		return 0;
	}
	*lenpub = dwPublicKeyLen;
	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, *pbPublicKey, &dwPublicKeyLen))
	{
		return 0;
	}
	// Get private key size
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwPrivateKeyLen))
	{
		return 0;
	}
	if (!(*pbPrivateKey = (BYTE*)malloc(dwPrivateKeyLen)))
	{
		return 0;
	}
	*lenpri = dwPrivateKeyLen;
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, *pbPrivateKey, &dwPrivateKeyLen))
	{
		return 0;
	}
	if (hKey) CryptDestroyKey(hKey);
	if (hProv)CryptReleaseContext(hProv, 0);
	return 1;
}

int encrypt_private_key(string passPhrase, BYTE ** privateKey, int len)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwCount;

	if (!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		return 0;
	}
	// Hash the password. 
	if (!CryptHashData(hHash, (BYTE *)passPhrase.c_str(), passPhrase.length(), 0))
	{
		return 0;
	}
	// Derive a session key from the hash object. 
	if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_NO_SALT, &hKey))
	{
		return 0;
	}
	// Encrypt data. 
	dwCount = len;
	if (!CryptEncrypt(hKey, 0, TRUE, 0, *privateKey, &dwCount, len))
	{
		return 0;
	}
	if (hHash) CryptDestroyHash(hHash);
	if (hKey) CryptDestroyKey(hKey);
	if (hProv) CryptReleaseContext(hProv, 0);

	return 1;
}

int decrypt_private_key(string passPhrase, BYTE ** privateKey, int * len)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwCount;

	if (!CryptAcquireContext(&hProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		return 0;
	}
	// Hash the password. 
	if (!CryptHashData(hHash, (BYTE *)passPhrase.c_str(), passPhrase.length(), 0))
	{
		return 0;
	}
	// Derive a session key from the hash object. 
	if (!CryptDeriveKey(hProv, CALG_RC4, hHash, CRYPT_NO_SALT, &hKey))
	{
		return 0;
	}
	// Encrypt data. 
	dwCount = *len;
	if (!CryptDecrypt(hKey, 0, TRUE, 0, *privateKey, &dwCount))
	{
		return 0;
	}
	*len = dwCount;
	if (hHash) CryptDestroyHash(hHash);
	if (hKey) CryptDestroyKey(hKey);
	if (hProv) CryptReleaseContext(hProv, 0);

	return 1;
}

int encrypt_file(wstring sourceFile, BYTE* publickey, int len, int algo)
{
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hPublic;
	DWORD dwKeyLength;
	DWORD dwCount;
	ALG_ID alg;
	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(sourceFile.c_str(),FILE_READ_DATA,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{
		return 0;
	}
	//---------------------------------------------------------------
	// Open the destination file. 
	wstring destinationFile = sourceFile + L".crypt";
	hDestinationFile = CreateFile(destinationFile.c_str(),FILE_WRITE_DATA,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
		return 0;
	}
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	switch (algo) {
	case 0:
		alg = CALG_3DES;	
		break;
	case 1:
		alg = CALG_RC2;
		break;
	case 2:
		alg = CALG_RC4;
	}
	// Generate session key. 
	if (!CryptGenKey(hProv, (ALG_ID)alg ,CRYPT_EXPORTABLE,&hKey))
	{
		return 0;
	}
	//Get lenght key
	CryptGetKeyParam(hKey, KP_KEYLEN,(BYTE*)&dwKeyLength, &dwCount, 0);

	// Import publickey
	if (!CryptImportKey(hProv, publickey, len ,0, CRYPT_EXPORTABLE,&hPublic))
	{
		return 0;
	}
	// Get lenght export hkey 
	if (!CryptExportKey(hKey,hPublic,SIMPLEBLOB,0,NULL,&dwCount))
	{
		return 0;
	}
	BYTE * bhKey = (BYTE*)malloc(dwCount);
	//Get export hkey
	if (!CryptExportKey(hKey,hPublic,SIMPLEBLOB,0,bhKey,&dwCount))
	{
		return 0;
	}
	DWORD lenKey = dwCount;
	//Write len key;
	if (!WriteFile(hDestinationFile, &lenKey, sizeof(DWORD),&dwCount, NULL))
	{
		return 0;
	}
	//Write key
	if (!WriteFile(hDestinationFile, bhKey, lenKey, &dwCount, NULL))
	{
		return 0;
	}
	//-----------------------------------------------------------
	DWORD dwBlockLen = dwKeyLength / 8;
	BYTE * pbBuffer = (BYTE *)malloc(dwBlockLen);
	bool fEOF = FALSE;
	do
	{
		if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL))
			return 0;
		if (dwCount < dwBlockLen)
			fEOF = TRUE;
		if (!CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBlockLen))
			return 0;
		if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
			return 0;
	} while (!fEOF);

	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}
	if (pbBuffer) free(pbBuffer);
	if (bhKey) free(bhKey);
	if (hKey) CryptDestroyKey(hKey);
	if (hPublic) CryptDestroyKey(hPublic);
	if (hProv) CryptReleaseContext(hProv, 0);
	return 1;
}

int decrypt_file(wstring sourceFile, BYTE * privatekey, int len)
{
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hPrivate = NULL;
	DWORD dwKeyLength;
	DWORD lenKeyEncrypt = 0;
	DWORD dwCount;
	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(sourceFile.c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
	{
		return 0;
	}
	//---------------------------------------------------------------
	// Open the destination file. 
	wstring destinationFile = sourceFile.erase(sourceFile.length() - 6, sourceFile.length());
	destinationFile = destinationFile + L".decrypt";
	hDestinationFile = CreateFile(destinationFile.c_str(), FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
	{
		return 0;
	}
	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	//Get lenght key
	if (!ReadFile(hSourceFile, &lenKeyEncrypt, sizeof(DWORD), &dwCount, NULL))
		return 0;

	BYTE * sessionKey = (BYTE*)malloc(lenKeyEncrypt);
	if (!ReadFile(hSourceFile, sessionKey, lenKeyEncrypt, &dwCount, NULL))
		return 0;

	// Get handle privatekey;
	if (!CryptImportKey(hProv, privatekey, len, 0, 0 , &hPrivate))
	{
		return 0;
	}
	// Get handle hkey 
	if (!CryptImportKey(hProv, sessionKey, lenKeyEncrypt, hPrivate, NULL, &hKey))
	{
		return 0;
	}
	//Get real lenght key
	CryptGetKeyParam(hKey, KP_KEYLEN, (BYTE*)&dwKeyLength, &dwCount, 0);

	//-----------------------------------------------------------
	DWORD dwBlockLen = dwKeyLength / 8;
	BYTE * pbBuffer = (BYTE *)malloc(dwBlockLen);
	bool fEOF = FALSE;
	do
	{
		if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL))
			return 0;
		if (dwCount < dwBlockLen)
			fEOF = TRUE;
		if (!CryptDecrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount))
			return 0;
		if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL))
			return 0;
	} while (!fEOF);

	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}
	if (sessionKey) free(sessionKey);
	if (pbBuffer) free(pbBuffer);
	if (hKey) CryptDestroyKey(hKey);
	if (hPrivate) CryptDestroyKey(hPrivate);
	if (hProv) CryptReleaseContext(hProv, 0);
	return 1;
}


int sign_file(wstring sourceFile, BYTE * privatekey, int len)
{
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	HCRYPTKEY hPrivate = NULL;
	DWORD dwCount;


	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(sourceFile.c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
		return 0;
	//---------------------------------------------------------------
	// Open the destination file. 
	wstring destinationFile = sourceFile + L".sig";
	hDestinationFile = CreateFile(destinationFile.c_str(), FILE_WRITE_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hDestinationFile)
		return 0;

	//Create hash
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		return 0;
	}
	LARGE_INTEGER dwLen;
	GetFileSizeEx(hSourceFile,&dwLen);
	BYTE * pbBuffer = (BYTE *)malloc(dwLen.LowPart);

	if (!ReadFile(hSourceFile, pbBuffer, dwLen.LowPart, &dwCount, NULL))
		return 0;
	if (!CryptHashData(hHash, pbBuffer, dwCount, 0))
		return 0;

	// Get handle privatekey;
	if (!CryptImportKey(hProv, privatekey, len, 0, 0, &hPrivate))
		return 0;

	DWORD dwSiglen = 0;
	if (!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, NULL, &dwSiglen))
		return 0;

	BYTE * pbSignature = (BYTE *)malloc(dwSiglen);

	if (!CryptSignHash(hHash, AT_KEYEXCHANGE, NULL, 0, pbSignature, &dwSiglen))
		return 0;

	if (!WriteFile(hDestinationFile, pbSignature, dwSiglen, &dwCount, NULL))
		return 0;
	
	//-----------------------------------------------------------
	
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hDestinationFile)
	{
		CloseHandle(hDestinationFile);
	}

	if (hHash) CryptDestroyHash(hHash);
	if (pbBuffer) free(pbBuffer);
	if (pbSignature) free(pbSignature);
	if (hPrivate) CryptDestroyKey(hPrivate);
	if (hProv) CryptReleaseContext(hProv, 0);
	return 1;
}

int check_sign(wstring sourceFile, wstring sourceSign, BYTE * publicKey, int len)
{
	HANDLE hSourceFile = INVALID_HANDLE_VALUE;
	HANDLE hSourceSign = INVALID_HANDLE_VALUE;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	HCRYPTKEY hPublic = NULL;
	DWORD dwCount;

	if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
		return 0;
	}
	//---------------------------------------------------------------
	// Open the source file. 
	hSourceFile = CreateFile(sourceFile.c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
		return 0;
	//---------------------------------------------------------------
	// Open the destination file.
	hSourceSign = CreateFile(sourceSign.c_str(), FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == hSourceFile)
		return 0;

	//Create hash
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		return 0;
	}

	LARGE_INTEGER dwLen;
	GetFileSizeEx(hSourceSign, &dwLen);
	BYTE * pbSign = (BYTE *)malloc(dwLen.LowPart);

	if (!ReadFile(hSourceSign, pbSign, dwLen.LowPart, &dwCount, NULL))
		return 0;

	DWORD dwSign = dwCount;

	GetFileSizeEx(hSourceFile, &dwLen);
	BYTE * pbBuffer = (BYTE *)malloc(dwLen.LowPart);

	if (!ReadFile(hSourceFile, pbBuffer, dwLen.LowPart, &dwCount, NULL))
		return 0;
	if (!CryptHashData(hHash, pbBuffer, dwCount, 0))
		return 0;

	if (!CryptImportKey(hProv, publicKey, len, 0, 0, &hPublic))
		return 0;


	if (!CryptVerifySignature(hHash, pbSign, dwSign, hPublic, 0, 0))
	{	
		return 0;
	}

	//-----------------------------------------------------------
	if (hSourceFile)
	{
		CloseHandle(hSourceFile);
	}

	if (hSourceSign)
	{
		CloseHandle(hSourceSign);
	}

	if (hHash) CryptDestroyHash(hHash);
	if (pbSign) free(pbSign);
	if (pbBuffer) free(pbBuffer);

	if (hPublic) CryptDestroyKey(hPublic);
	if (hProv) CryptReleaseContext(hProv, 0);
	return 1;
}


int ByteToBase64(const BYTE * pSrc, int nLenSrc, string & res, int nLenDst)
{
	DWORD nLenOut = nLenDst;
	BOOL fRet = CryptBinaryToStringA((const BYTE*)pSrc, nLenSrc, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &nLenOut);
	char * pDst = new char[nLenOut];
	fRet = CryptBinaryToStringA((const BYTE*)pSrc, nLenSrc, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, pDst, &nLenOut);
	res.clear();
	res.assign(pDst);
	delete[] pDst;
	return(nLenOut);
}

int Base64ToByte(string pSrc, int nLenSrc, BYTE ** res, int nLenDst)
{
	DWORD nLenOut = nLenDst;
	BOOL fRet = CryptStringToBinaryA((LPCSTR)pSrc.c_str(), nLenSrc, CRYPT_STRING_BASE64, NULL, &nLenOut, NULL, NULL);
	BYTE * pDst = new BYTE[nLenOut];
	fRet = CryptStringToBinaryA((LPCSTR)pSrc.c_str(), nLenSrc, CRYPT_STRING_BASE64, pDst, &nLenOut, NULL, NULL);
	*res = pDst;
	return(nLenOut);
}