#include "Account.h"
#include <Wincrypt.h>

CAccount::CAccount()
{
	email = "";
	pass = "";
	name = L"";
	birthday = "";
	phone = "";
	address = L"";
	salt = 0;
	publicKey = "";
	privateKey = "";
}


CAccount::CAccount(string _email)
{
	email = _email;
	pass = "";
	name = L"";
	birthday = "";
	phone = "";
	address = L"";
	salt = 0;
	publicKey = "";
	privateKey = "";
}

CAccount::CAccount(string _email, string _pass, wstring _name, string
	_birthday, string _phone, wstring _address,int _salt,string _publickey,string _privatekey)
{
	 email = _email;
	 pass = _pass;
	 name = _name;
	 birthday = _birthday;
	 phone = _phone;
	 address = _address;
	 salt = _salt;
	 publicKey = _publickey;
	 privateKey = _privatekey;
}
bool CAccount::WriteToXML()
{
	xml_document doc;
	xml_node root;
	xml_parse_result result = doc.load_file("data.xml",parse_default | parse_declaration);
	if (!result)
	{
		auto declarationNode = doc.append_child(node_declaration);
		declarationNode.append_attribute("version") = "1.0";
		declarationNode.append_attribute("encoding") = "utf-8";
		declarationNode.append_attribute("standalone") = "yes";
		root = doc.append_child("UserAccounts");
		doc.save_file("data.xml", PUGIXML_TEXT("  "));
	}
	root = doc.document_element();
	//kiem tra co trung email chua
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (xpathNode)
		return 0;
	xml_node account = root.append_child("Account");
	account.append_attribute("email") = email.c_str();

	xml_node nodeChild  = account.append_child("name");
	nodeChild.append_child(node_pcdata).set_value(pugi::as_utf8(name).c_str());
	
	xml_node nodeChild1 = account.append_child("salt");
	nodeChild1.append_child(node_pcdata).set_value(to_string(salt).c_str());

	xml_node nodeChild2 = account.append_child("passphrase");
	nodeChild2.append_child(node_pcdata).set_value(pass.c_str());

	xml_node nodeChild3 = account.append_child("birthday");
	nodeChild3.append_child(node_pcdata).set_value(birthday.c_str());

	xml_node nodeChild4 = account.append_child("phone");
	nodeChild4.append_child(node_pcdata).set_value(phone.c_str());

	xml_node nodeChild5 = account.append_child("address");
	nodeChild5.append_child(node_pcdata).set_value(pugi::as_utf8(address).c_str());
	
	xml_node nodeChild7 = account.append_child("publickey");
	nodeChild7.append_child(node_pcdata).set_value(publicKey.c_str());

	xml_node nodeChild8 = account.append_child("privatekey");
	nodeChild8.append_child(node_pcdata).set_value(privateKey.c_str());
	doc.save_file("data.xml", PUGIXML_TEXT("  "));

	return 1;
}

bool CAccount::CheckUser(string _password)
{
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return 0;
	xml_node account = xpathNode.node();
	int _salt = atoi(account.child("salt").child_value());
	string _pass = (account.child("passphrase").child_value());
	_password = _password + to_string(_salt);
	BYTE * hash = NULL;
	long lenhash;
	make_hash(_password.c_str(), &hash, &lenhash);
	ByteToBase64(hash, lenhash, _password, lenhash);
	free(hash);
	if (_password == _pass)
		return 1;
	return 0;
}

bool CAccount::GetAll()
{
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return 0;
	xml_node account = xpathNode.node();
	this->name = as_wide(account.child("name").child_value());
	this->address = as_wide(account.child("address").child_value());
	this->birthday = account.child("birthday").child_value();
	this->phone = account.child("phone").child_value();
	this->privateKey = account.child("privatekey").child_value();
	this->publicKey = account.child("publickey").child_value();
	this->pass = account.child("passphrase").child_value();
	this->salt = atoi(account.child("salt").child_value());
	return 1;
}

bool CAccount::GetInfo()
{
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return 0;
	xml_node account = xpathNode.node();
	this->name = as_wide(account.child("name").child_value());
	this->address = as_wide(account.child("address").child_value());
	this->birthday = account.child("birthday").child_value();
	this->phone = account.child("phone").child_value();
	return 1;
}

bool CAccount::UpdateToXML()
{
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return 0;
	xml_node account = xpathNode.node();
	account.child("name").first_child().set_value(pugi::as_utf8(name).c_str());
	account.child("salt").first_child().set_value(to_string(salt).c_str());
	account.child("passphrase").first_child().set_value(pass.c_str());
	account.child("birthday").first_child().set_value(birthday.c_str());
	account.child("phone").first_child().set_value(phone.c_str());
	account.child("address").first_child().set_value(pugi::as_utf8(address).c_str());
	doc.save_file("data.xml", PUGIXML_TEXT("  "));
	return 1;
}

bool CAccount::ExportKey(wstring out)
{
	this->GetAll();
	xml_document doc;
	auto declarationNode = doc.append_child(node_declaration);
	declarationNode.append_attribute("version") = "1.0";
	declarationNode.append_attribute("encoding") = "utf-8";
	declarationNode.append_attribute("standalone") = "yes";
	doc.append_child("Account");

	xml_node root = doc.document_element();

	xml_node nodeChild7 = root.append_child("publickey");
	nodeChild7.append_child(node_pcdata).set_value(publicKey.c_str());

	xml_node nodeChild8 = root.append_child("privatekey");
	nodeChild8.append_child(node_pcdata).set_value(privateKey.c_str());

	xml_node nodeChild = root.append_child("name");
	nodeChild.append_child(node_pcdata).set_value(pugi::as_utf8(name).c_str());

	xml_node nodeChild1 = root.append_child("salt");
	nodeChild1.append_child(node_pcdata).set_value(to_string(salt).c_str());

	xml_node nodeChild2 = root.append_child("passphrase");
	nodeChild2.append_child(node_pcdata).set_value(pass.c_str());

	xml_node nodeChild3 = root.append_child("birthday");
	nodeChild3.append_child(node_pcdata).set_value(birthday.c_str());

	xml_node nodeChild4 = root.append_child("phone");
	nodeChild4.append_child(node_pcdata).set_value(phone.c_str());
	
	xml_node nodeChild5 = root.append_child("address");
	nodeChild5.append_child(node_pcdata).set_value(pugi::as_utf8(address).c_str());

	doc.save_file(out.c_str(), PUGIXML_TEXT("  "));
	return 1;
}

bool CAccount::ImportKey(wstring out)
{
	//Get data 
	xml_document doc;
	xml_parse_result result = doc.load_file(out.c_str(), parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	this->publicKey = root.child("publickey").child_value();
	this->privateKey = root.child("privatekey").child_value();
	this->name = as_wide(root.child("name").child_value());
	this->salt = atoi(root.child("salt").child_value());
	this->pass = root.child("passphrase").child_value();
	this->birthday = root.child("birthday").child_value();
	this->phone = root.child("phone").child_value();
	this->address = as_wide(root.child("address").child_value());

	//change data
	xml_document doc2;
	result = doc2.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root2 = doc2.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root2.select_node(query.c_str());
	if (!xpathNode)
		return 0;
	xml_node account = xpathNode.node();
	account.child("name").first_child().set_value(pugi::as_utf8(name).c_str());
	account.child("salt").first_child().set_value(to_string(salt).c_str());
	account.child("passphrase").first_child().set_value(pass.c_str());
	account.child("birthday").first_child().set_value(birthday.c_str());
	account.child("phone").first_child().set_value(phone.c_str());
	account.child("address").first_child().set_value(pugi::as_utf8(address).c_str());
	account.child("publickey").first_child().set_value(publicKey.c_str());
	account.child("privatekey").first_child().set_value(privateKey.c_str());
	doc2.save_file("data.xml", PUGIXML_TEXT("  "));
	return 1;
}

string CAccount::Getemail()
{
	return email;
}
string CAccount::Getpass()
{
	return pass;
}
wstring CAccount::Getname()
{
	return name;
}
string CAccount::Getbirthday()
{
	return birthday;
}
string CAccount::Getphone()
{
	return phone;
}
wstring CAccount::Getaddress()
{
	return address;
}
int CAccount::Getsalt()
{
	return salt;
}
string CAccount::GetpublicKey()
{
	if(publicKey.length() > 0)
		return publicKey;
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return "none";
	xml_node account = xpathNode.node();
	this->publicKey = account.child("publickey").child_value();
	return publicKey;
}
string CAccount::GetprivateKey()
{
	if (privateKey.length() > 0)
		return privateKey;
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	//tim email trong xml
	string query = "//Account[@email=\'" + email + "\']";
	xpath_node xpathNode = root.select_node(query.c_str());
	if (!xpathNode)
		return "none";
	xml_node account = xpathNode.node();
	this->privateKey = account.child("privatekey").child_value();
	return privateKey;
}

void CAccount::Setemail(string t)
{
	email = t;
}
void CAccount::Setpass(string t)
{
	pass = t;
}
void CAccount::Setname(wstring t)
{
	name = t;
}
void CAccount::Setbirthday(string t)
{
	birthday = t;
}
void CAccount::Setphone(string t)
{
	phone = t;
}
void CAccount::Setaddress(wstring t)
{
	address = t;
}
void CAccount::Setsalt(int t)
{
	salt = t;
}

CAccount::~CAccount()
{

}