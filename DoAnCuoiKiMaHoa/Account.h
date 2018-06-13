#pragma once
#include "Support.h"
#include "pugixml.hpp"
using namespace pugi;

class CAccount
{
	string email;
	string pass;
	wstring name;
	string birthday;
	string phone;
	wstring address;	
	int salt;
	string publicKey;
	string privateKey;
	bool GetAll();
public:
	CAccount();
	CAccount(string);
	CAccount(string, string, wstring, string, string, wstring, int,string,string);
	bool GetInfo();
	bool CheckUser(string);
	bool WriteToXML();
	bool UpdateToXML();
	bool ImportKey(wstring);
	bool ExportKey(wstring);
	string Getemail();
	string Getpass();
	wstring Getname();
	string Getbirthday();
	string Getphone();
	wstring Getaddress();
	int Getsalt();
	string GetpublicKey();
	string GetprivateKey();

	void Setemail(string);
	void Setpass(string);
	void Setname(wstring);
	void Setbirthday(string);
	void Setphone(string);
	void Setaddress(wstring);
	void Setsalt(int);
	~CAccount();
};