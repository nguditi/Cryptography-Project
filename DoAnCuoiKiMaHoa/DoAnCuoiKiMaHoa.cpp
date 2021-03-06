// DoAnCuoiKiMaHoa.cpp : Defines the entry point for the application.
//
#include "stdafx.h"
#include "DoAnCuoiKiMaHoa.h"
#include <Commdlg.h>
#include <CommCtrl.h>
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HWND _hWnd;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Signup(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Update(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Login(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    ImEx(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Encrypt(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Decrypt(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Loading(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Sign(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    Veri(HWND, UINT, WPARAM, LPARAM);








void SetCenter(HWND hDlg);


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.
	srand((unsigned)time(NULL));
    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_DOANCUOIKIMAHOA, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_DOANCUOIKIMAHOA));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_DOANCUOIKIMAHOA));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_DOANCUOIKIMAHOA);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   POINT p;
   HWND desktop = GetDesktopWindow();
   RECT rect;
   GetWindowRect(desktop, &rect);
   p.x = (rect.right - rect.left - 400) / 2;
   p.y = (rect.bottom - rect.top - 500) / 2;

   HWND hWnd = CreateWindowW(szWindowClass, L"Crypto", WS_BORDER | WS_MINIMIZEBOX | WS_ICONIC | WS_VISIBLE | WS_SYSMENU,
	   p.x, p.y, 400, 500, nullptr, nullptr, hInstance, nullptr);
   _hWnd = hWnd;
   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//

static LOGFONT l;
static HFONT h;
static int option;
static string curEmail;
static string curPass;
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
	case WM_CREATE:
	{
		wcscpy_s(l.lfFaceName, L"Tahoma");
		l.lfHeight = 18;
		l.lfWidth = 9;
		h = CreateFontIndirect(&l);

		HWND btn1 = CreateWindow(L"Button", L"Đăng kí", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 25, 200, 40, hWnd, (HMENU)ID_SIGNUP_BTN, hInst, 0);	
		SendMessage(btn1, WM_SETFONT, (WPARAM)h, 1);

		HWND btn2 = CreateWindow(L"Button", L"Cập nhật thông tin", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 75, 200, 40, hWnd, (HMENU)ID_UPDATE_BTN, hInst, 0);
		SendMessage(btn2, WM_SETFONT, (WPARAM)h, 1);

		HWND btn3 = CreateWindow(L"Button", L"Import/Export khóa", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 125, 200, 40, hWnd, (HMENU)ID_IMEX_BTN, hInst, 0);
		SendMessage(btn3, WM_SETFONT, (WPARAM)h, 1);

		HWND btn4 = CreateWindow(L"Button", L"Mã hóa tập tin", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 175, 200, 40, hWnd, (HMENU)ID_ENCRYPT_BTN, hInst, 0);
		SendMessage(btn4, WM_SETFONT, (WPARAM)h, 1);

		HWND btn5 = CreateWindow(L"Button", L"Giải mã tập tin", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 225, 200, 40, hWnd, (HMENU)ID_DECRYPT_BTN, hInst, 0);
		SendMessage(btn5, WM_SETFONT, (WPARAM)h, 1);

		HWND btn6 = CreateWindow(L"Button", L"Kí trên tập tin", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 275, 200, 40, hWnd, (HMENU)ID_SIGN_BTN, hInst, 0);
		SendMessage(btn6, WM_SETFONT, (WPARAM)h, 1);

		HWND btn7 = CreateWindow(L"Button", L"Xác nhận chữ kí", WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 95, 325, 200, 40, hWnd, (HMENU)ID_VERI_BTN, hInst, 0);
		SendMessage(btn7, WM_SETFONT, (WPARAM)h, 1);
	}
	break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
			case ID_SIGNUP_BTN:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_SIGNUP), hWnd, Signup);
				break;
			case ID_ENCRYPT_BTN:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_ENCRYPT), hWnd, Encrypt);
				break;
			case ID_UPDATE_BTN:
				option = IDD_UPDATE;
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGIN), hWnd, Login);
				break;
			case ID_IMEX_BTN:
				option = IDD_IMEX;
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGIN), hWnd, Login);
				break;
			case ID_VERI_BTN:
				DialogBox(hInst, MAKEINTRESOURCE(IDD_VERI), hWnd, Veri);
				break;
			case ID_DECRYPT_BTN:
				option = IDD_DECRYPT;
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGIN), hWnd, Login);
				break;
			case ID_SIGN_BTN:
				option = IDD_SIGN;
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGIN), hWnd, Login);
				break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

INT_PTR CALLBACK Signup(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static int lenkey = 512;
	static WCHAR wtmp[256];
	static CHAR ctmp[256];
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetCenter(hDlg);
		_itow_s(lenkey, wtmp, 10);
		SetDlgItemText(hDlg, IDC_EDIT8, wtmp);
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		int wmId = LOWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDOK:
		{
			GetDlgItemTextA(hDlg,IDC_EDIT6, ctmp, 256);
			string email(ctmp);
			GetDlgItemTextA(hDlg, IDC_EDIT1, ctmp, 256);
			string pass(ctmp);
			GetDlgItemText(hDlg, IDC_EDIT2, wtmp, 256);
			wstring name(wtmp);
			GetDlgItemTextA(hDlg, IDC_EDIT3, ctmp, 256);
			string birthday(ctmp);
			GetDlgItemTextA(hDlg, IDC_EDIT4, ctmp, 256);
			string phone(ctmp);
			GetDlgItemText(hDlg, IDC_EDIT5, wtmp, 256);
			wstring address(wtmp);

			if (email.find("'") != -1)
			{
				MessageBox(hDlg, L"Email chứa kí tự không hợp lệ", L"Lỗi", 0);
			}
			else if (email.length() == 0)
			{
				MessageBox(hDlg, L"Không thể để email trống", L"Thiếu email", 0);
			}
			else if (pass.length() == 0)
			{
				MessageBox(hDlg, L"Không thể để passphrase trống", L"Thiếu pass", 0);
			}
			else
			{
				//Generate ssh base64
				BYTE * b_publicKey = NULL;
				BYTE * b_privateKey = NULL;
				BYTE * hash = NULL;

				string strpublickey;
				string strprivatekey;
				long lenhash;
				int lenpub;
				int lenpri;

				gen_key_pair(&b_publicKey, &lenpub, &b_privateKey, &lenpri, lenkey);
				encrypt_private_key(pass, &b_privateKey, lenpri);

				//Random salt
				int salt = rand() + 10000;
				pass = pass + to_string(salt);
				//Hash passphrase
				make_hash(pass.c_str(), &hash, &lenhash);
				ByteToBase64(hash, lenhash, pass, lenhash);
				 				
				ByteToBase64(b_publicKey, lenpub,strpublickey, lenpub);

				ByteToBase64(b_privateKey, lenpri, strprivatekey, lenpri);

				CAccount account(email, pass, name, birthday, phone, address, salt, strpublickey, strprivatekey);
			
				free(b_publicKey);
				free(b_privateKey);
				free(hash);

				if(!account.WriteToXML())
					MessageBox(hDlg, L"Email này đã được đăng kí ", L"Email trùng", 0);
				else
				{
					MessageBox(hDlg, L"Tạo thành công ", L"Thông báo", 0);
					EndDialog(hDlg, LOWORD(wParam));
				}
				return (INT_PTR)TRUE;
			}	
			break;
		}
		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		case IDC_INCREASE:
		{
			if (lenkey == 1024)
				return (INT_PTR)TRUE;
			lenkey += 64;
			WCHAR tmp[256];
			_itow_s(lenkey, tmp, 10);
			SetDlgItemText(hDlg, IDC_EDIT8, tmp);
			return (INT_PTR)TRUE;
		}
		case IDC_DECREASE:
		{
			if (lenkey == 512)
				return (INT_PTR)TRUE;
			lenkey -= 64;
			WCHAR tmp[256];
			_itow_s(lenkey, tmp, 10);
			SetDlgItemText(hDlg, IDC_EDIT8, tmp);
			return (INT_PTR)TRUE;
		}
		return (INT_PTR)TRUE;
		}
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK Login(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetCenter(hDlg);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK)
		{
			static CHAR ctmp[256];
			GetDlgItemTextA(hDlg, IDC_EDITL2, ctmp, 256);
			string email(ctmp);
			GetDlgItemTextA(hDlg, IDC_EDITL1, ctmp, 256);
			string pass(ctmp);
			CAccount ac(email);
			if (email.find("'") != -1)
			{
				MessageBox(hDlg, L"Không tồn tại email hoặc sai mật khẩu", L"Thất bại", 0);
			}
			else if (ac.CheckUser(pass))
			{
				EndDialog(hDlg, LOWORD(wParam));
				curEmail = email;
				switch (option)
				{
				case IDD_UPDATE:
					DialogBox(hInst, MAKEINTRESOURCE(option), _hWnd, Update);
					break;
				case IDD_IMEX:
					DialogBox(hInst, MAKEINTRESOURCE(option), _hWnd, ImEx);
					break;
				case IDD_DECRYPT:
					curPass = pass;
					DialogBox(hInst, MAKEINTRESOURCE(option), _hWnd, Decrypt);
					break;
				case IDD_SIGN:
					curPass = pass;
					DialogBox(hInst, MAKEINTRESOURCE(option), _hWnd, Sign);
					break;
				}
			}
			else
			{
				MessageBox(hDlg, L"Không tồn tại email hoặc sai mật khẩu", L"Thất bại", 0);
			}
			return (INT_PTR)TRUE;
		}
		if(LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}


INT_PTR CALLBACK Update(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetCenter(hDlg);
		CAccount ac(curEmail);
		ac.GetInfo();
		SetDlgItemTextA(hDlg, IDC_EDITU6, ac.Getemail().c_str());
		SetDlgItemText(hDlg, IDC_EDITU2, ac.Getname().c_str());
		SetDlgItemTextA(hDlg, IDC_EDITU3, ac.Getbirthday().c_str());
		SetDlgItemTextA(hDlg, IDC_EDITU4, ac.Getphone().c_str());
		SetDlgItemText(hDlg, IDC_EDITU5, ac.Getaddress().c_str());
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_CHECK1)
		{
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
				if (SendDlgItemMessage(hDlg, IDC_CHECK1, BM_GETCHECK, 0, 0))
				{
					SendMessage(GetDlgItem(hDlg, IDC_EDITU1), EM_SETREADONLY, 0, 0);
					SendMessage(GetDlgItem(hDlg, IDC_EDITU7), EM_SETREADONLY, 0, 0);
				}
				else
				{
					SendMessage(GetDlgItem(hDlg, IDC_EDITU1), EM_SETREADONLY, 1, 0);
					SendMessage(GetDlgItem(hDlg, IDC_EDITU7), EM_SETREADONLY, 1, 0);
					SetDlgItemTextA(hDlg, IDC_EDITU1, "");
					SetDlgItemTextA(hDlg, IDC_EDITU7, "");
				}
			}
			return (INT_PTR)TRUE;
		}
		else if (LOWORD(wParam) == IDOK)
		{
			WCHAR wtmp[256];
			CHAR ctmp[256];
			GetDlgItemTextA(hDlg, IDC_EDITU1, ctmp, 256);
			string pass1(ctmp);
			GetDlgItemTextA(hDlg, IDC_EDITU7, ctmp, 256);
			string pass2(ctmp);
			GetDlgItemText(hDlg, IDC_EDITU2, wtmp, 256);
			wstring name(wtmp);
			GetDlgItemTextA(hDlg, IDC_EDITU3, ctmp, 256);
			string birthday(ctmp);
			GetDlgItemTextA(hDlg, IDC_EDITU4, ctmp, 256);
			string phone(ctmp);
			GetDlgItemText(hDlg, IDC_EDITU5, wtmp, 256);
			wstring address(wtmp);		
			if (pass1 != pass2)
			{
				MessageBox(hDlg, L"Mật khẩu nhập lại không khớp", L"Nhập sai", 0);
				SetDlgItemTextA(hDlg, IDC_EDITU1,"");
				SetDlgItemTextA(hDlg, IDC_EDITU7,"");
			}
			else if (pass1.length() == 0)
			{
				MessageBox(hDlg, L"Không thể để passphrase trống", L"Thiếu pass", 0);
			}
			else
			{
				bool want = 0;
				want = MessageBox(hDlg, L"Cập nhật thông tin?", L"Lưu ý", MB_OKCANCEL);
				if (want)
				{
					BYTE * hash = NULL;
					long lenhash;
					//Random salt
					int salt = rand() + 10000;
					pass1 = pass1 + to_string(salt);
					//Hash passphrase
					make_hash(pass1.c_str(), &hash, &lenhash);
					ByteToBase64(hash, lenhash, pass1, lenhash);
					CAccount ac(curEmail);
					ac.Setname(name);
					ac.Setbirthday(birthday);
					ac.Setaddress(address);
					ac.Setphone(phone);
					ac.Setsalt(salt);
					ac.Setpass(pass1);
					if (ac.UpdateToXML())
						MessageBox(hDlg, L"Thay đổi thành công", L"Thông báo", 0);
					else
						MessageBox(hDlg, L"Có lỗi xảy ra, vui lòng thử lại", L"Thông báo", 0);

					free(hash);
				}
				EndDialog(hDlg, LOWORD(wParam));
				curEmail.clear();
				return (INT_PTR)TRUE;
			}
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			curEmail.clear();
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK ImEx(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetCenter(hDlg);
		SetDlgItemTextA(hDlg, IDC_EDITIX2, curEmail.c_str());
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_IMPORT:
		{
			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITIX1, filename, 256);
			CAccount ac(curEmail);
			if (wcslen(filename) == 0)
			{
				MessageBox(hDlg, L"Chọn file import", L"Chọn file", 0);
				return (INT_PTR)TRUE;
			}
			if (ac.ImportKey(wstring(filename)))
				MessageBox(hDlg, L"Import thành công", L"Thông báo", 0);
			else
				MessageBox(hDlg, L"Có lỗi xảy ra, vui lòng thử lại", L"Thông báo", 0);
			return (INT_PTR)TRUE;
		}
		case IDC_EXPORT:
		{
			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITIX3, filename, 256);
			if (wcslen(filename) == 0)
			{
				MessageBox(hDlg, L"Đặt tên file export", L"Chọn file", 0);
				return (INT_PTR)TRUE;
			}
			CAccount ac(curEmail);
			if (ac.ExportKey(wstring(filename)))
				MessageBox(hDlg, L"Export thành công", L"Thông báo", 0);
			else
				MessageBox(hDlg, L"Có lỗi xảy ra, vui lòng thử lại", L"Thông báo", 0);
			return (INT_PTR)TRUE;
		}
		case IDC_IMPORT2:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"Key data (*.xml)\0*.xml\0All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITIX1, filename);
			return (INT_PTR)TRUE;
		}
		case IDC_EXPORT2:
		{	
			WCHAR filename[256] = L"export-key";
			OPENFILENAME ofn;
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"Key data (*.xml)\0*.xml\0All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 2;
			ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
			ofn.lpstrFile = filename;
			ofn.lpstrDefExt = L"xml";
			if(GetSaveFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITIX3, filename);
			return (INT_PTR)TRUE;			
		}
		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			curEmail.clear();
			return (INT_PTR)TRUE;
		}
		return (INT_PTR)TRUE;
		}
	}
	return (INT_PTR)FALSE;
}

//Asyn
static HWND _hDlg;
struct PARAM
{
	wstring sign;
	wstring name;
	BYTE * key;
	int len;
	int algo;
};

static PARAM * p;

HANDLE thread;
DWORD WINAPI DoProcess(LPVOID t)
{
	if (encrypt_file(p->name, p->key, p->len, p->algo))
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Mã hóa thành công", L"Thông báo", 0);
	}
	else
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Mã hóa không thành công", L"Thông báo", 0);
	}
	delete[] p->key;
	delete p;
	TerminateThread(thread, 0);
	return 1;
}

INT_PTR CALLBACK Encrypt(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetCenter(hDlg);
		SendMessage(GetDlgItem(hDlg, IDC_COMBOAL), CB_ADDSTRING, NULL, (LPARAM)L"RC4");
		SendMessage(GetDlgItem(hDlg, IDC_COMBOAL), CB_ADDSTRING, NULL, (LPARAM)L"3-DES");
		SendMessage(GetDlgItem(hDlg, IDC_COMBOAL), CB_ADDSTRING, NULL, (LPARAM)L"RC2");
		SendMessage(GetDlgItem(hDlg, IDC_COMBOAL),CB_SETCURSEL,0 , 0);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BROWSE2:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITEN, filename);
			return (INT_PTR)TRUE;
		}
		case IDOK:
		{
			CHAR email[256];
			GetDlgItemTextA(hDlg, IDC_EDITEN2, email, 256);
			string strEmail(email);

			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITEN, filename, 256);
			wstring strfilename(filename);

			if (strfilename.length() == 0)
			{
				MessageBox(hDlg, L"Chọn file mã hóa", L"Chọn file", 0);
			}
			else if (strEmail.length() == 0)
			{
				MessageBox(hDlg, L"Nhập email người nhận", L"Thiếu email", 0);
			}
			else
			{
				CAccount ac(strEmail);
				string pub = ac.GetpublicKey();
				if (pub == "none")
				{
					MessageBox(hDlg, L"Không tìm thấy email", L"Lỗi", 0);
					return (INT_PTR)TRUE;
				}
				BYTE * b_Pub = NULL;
				int len = Base64ToByte(pub, pub.length(), &b_Pub, pub.length());
				int algo = SendMessage(GetDlgItem(hDlg, IDC_COMBOAL), CB_GETCURSEL, 0, 0);	

				p = new PARAM;		
				p->algo = algo;
				p->key = new BYTE[len];
				memcpy_s(p->key, len,b_Pub, len);
				p->len = len;
				p->name = strfilename;
				thread = CreateThread(0, 0, DoProcess,0, 0, 0);
				if (b_Pub)
				{
					delete[] b_Pub;
				}
				EndDialog(hDlg, LOWORD(wParam));
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOADING), _hWnd, Loading);
			}
			return (INT_PTR)TRUE;
		}

		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		}
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}

DWORD WINAPI DoProcess1(LPVOID t)
{
	if (decrypt_file(p->name, p->key, p->len))
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Giải mã thành công", L"Thông báo", 0);
	}
	else
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Giải mã không thành công", L"Thông báo", 0);
	}
	delete[] p->key;
	delete p;
	TerminateThread(thread, 0);
	return 1;
}

INT_PTR CALLBACK Decrypt(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetCenter(hDlg);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BROWSE3:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITDE, filename);
			return (INT_PTR)TRUE;
		}
		case IDOK:
		{
			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITDE, filename, 256);
			wstring strfilename(filename);

			if (strfilename.length() == 0)
			{
				MessageBox(hDlg, L"Chọn file giải mã ", L"Chọn file", 0);
			}
			else
			{
				CAccount ac(curEmail);
				string pri = ac.GetprivateKey();
				BYTE * b_Pri = NULL;
				int len = Base64ToByte(pri, pri.length(), &b_Pri, pri.length());
				decrypt_private_key(curPass,&b_Pri,&len);
				curPass.clear();
				p = new PARAM;
				p->key = new BYTE[len];
				memcpy_s(p->key, len, b_Pri, len);
				p->len = len;
				p->name = strfilename;
				thread = CreateThread(0, 0, DoProcess1,0, 0, 0);
				if (b_Pri)
				{
					delete[] b_Pri;
				}
				EndDialog(hDlg, LOWORD(wParam));
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOADING), _hWnd, Loading);
			}
			return (INT_PTR)TRUE;
		}

		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		}
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}

DWORD WINAPI DoSign(LPVOID t)
{
	if (sign_file(p->name, p->key, p->len))
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Kí thành công", L"Thông báo", 0);
	}
	else
	{
		EndDialog(_hDlg, 0);
		MessageBox(_hWnd, L"Kí không thành công", L"Thông báo", 0);
	}
	delete[] p->key;
	delete p;
	TerminateThread(thread, 0);
	return 1;
}

INT_PTR CALLBACK Sign(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetCenter(hDlg);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BROWSESIGN:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITSI, filename);
			return (INT_PTR)TRUE;
		}
		case IDOK:
		{
			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITSI, filename, 256);
			wstring strfilename(filename);

			if (strfilename.length() == 0)
			{
				MessageBox(hDlg, L"Chọn file để kí ", L"Chọn file", 0);
			}
			else
			{
				CAccount ac(curEmail);
				string pri = ac.GetprivateKey();
				BYTE * b_Pri = NULL;
				int len = Base64ToByte(pri, pri.length(), &b_Pri, pri.length());
				decrypt_private_key(curPass, &b_Pri, &len);
				curPass.clear();
				p = new PARAM;
				p->key = new BYTE[len];
				memcpy_s(p->key, len, b_Pri, len);
				p->len = len;
				p->name = strfilename;
				thread = CreateThread(0, 0, DoSign, 0, 0, 0);
				if (b_Pri)
				{
					delete[] b_Pri;
				}
				EndDialog(hDlg, LOWORD(wParam));
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOADING), _hWnd, Loading);
			}
			return (INT_PTR)TRUE;
		}

		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		}
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}


DWORD WINAPI DoVeri(LPVOID t)
{
	xml_document doc;
	xml_parse_result result = doc.load_file("data.xml", parse_default | parse_declaration);
	if (!result)
		return 0;
	xml_node root = doc.document_element();
	for (xml_node_iterator it = root.begin(); it != root.end(); ++it)
	{
		string pub = it->child("publickey").child_value();
		BYTE * b_Pub = NULL;
		int len = Base64ToByte(pub, pub.length(), &b_Pub, pub.length());
		if (check_sign(p->name, p->sign, b_Pub, len))
		{
			wstring em = as_wide(it->attribute("email").value());
			EndDialog(_hDlg, 0);
			MessageBox(_hWnd, em.c_str(), L"Tìm thấy email", 0);
			delete[] b_Pub;
			delete p;
			TerminateThread(thread, 0);
			return 1;
		}
		if (b_Pub)
		{
			delete[] b_Pub;
		}
	}
	EndDialog(_hDlg, 0);
	MessageBox(_hWnd,L"Không có email phù hợp", L"Không tìm thấy", 0);
	delete p;
	TerminateThread(thread, 0);
	return 1;
}

INT_PTR CALLBACK Veri(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		SetCenter(hDlg);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BROWSEVE1:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITVE, filename);
			return (INT_PTR)TRUE;
		}
		case IDC_BROWSEVE2:
		{
			WCHAR filename[256];
			OPENFILENAME ofn;
			filename[0] = '\0';
			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hDlg;
			ofn.nMaxFile = 260;
			ofn.lpstrFilter = L"All files (*.*)\0*.*\0";
			ofn.nFilterIndex = 1;
			ofn.nMaxFileTitle = _MAX_FNAME + _MAX_EXT;
			ofn.lpstrFile = filename;
			ofn.Flags = OFN_HIDEREADONLY | OFN_CREATEPROMPT | OFN_NOCHANGEDIR | OFN_FILEMUSTEXIST;
			if (GetOpenFileName(&ofn))
				SetDlgItemText(hDlg, IDC_EDITVE1, filename);
			return (INT_PTR)TRUE;
		}
		case IDOK:
		{
			WCHAR sign[256];
			GetDlgItemText(hDlg, IDC_EDITVE1, sign, 256);
			wstring strsign(sign);

			WCHAR filename[256];
			GetDlgItemText(hDlg, IDC_EDITVE, filename, 256);
			wstring strfilename(filename);

			if (strfilename.length() == 0)
			{
				MessageBox(hDlg, L"Chọn file cần kiểm tra", L"Chọn file", 0);
			}
			else if (strsign.length() == 0)
			{
				MessageBox(hDlg, L"Chọn file chứa chữ ký", L"Chọn chữ kí", 0);
			}
			else
			{
				p = new PARAM;
				p->name = strfilename;
				p->sign = strsign;
				thread = CreateThread(0, 0, DoVeri, 0, 0, 0);
				EndDialog(hDlg, LOWORD(wParam));
				DialogBox(hInst, MAKEINTRESOURCE(IDD_LOADING), _hWnd, Loading);
			}
			return (INT_PTR)TRUE;
		}

		case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		}
		return (INT_PTR)TRUE;
	}
	return (INT_PTR)FALSE;
}

INT_PTR CALLBACK Loading(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
	{
		SetCenter(hDlg);
		HWND hwndProgressBar = GetDlgItem(hDlg, IDC_PROGRESS);
		long style = GetWindowLong(hwndProgressBar, GWL_STYLE);
		style = style | PBS_MARQUEE;
		SetWindowLong(hwndProgressBar, GWL_STYLE, style);
		_hDlg = hDlg;
		SendMessage(hwndProgressBar, PBM_SETMARQUEE, 1, 30);
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
	{
		if (LOWORD(wParam) == IDCANCEL)
		{
			bool want = 0;
			want = MessageBox(hDlg, L"Bạn muốn dừng quá trình này?", L"Thông báo", MB_OKCANCEL);
			if (want)
			{
				if(p->key) delete[] p->key;
				if(p) delete p;
				TerminateThread(thread, 0);
				EndDialog(hDlg, LOWORD(wParam));
			}
			return (INT_PTR)TRUE;
		}
	}
	}
	return (INT_PTR)FALSE;
}

void SetCenter(HWND hDlg)
{
	RECT rcOwner, rcDlg;
	HWND parent = GetParent(hDlg);
	GetWindowRect(parent, &rcOwner);
	GetWindowRect(hDlg, &rcDlg);
	SetWindowPos(hDlg,
		HWND_TOP,
		rcOwner.left + (rcOwner.right - rcOwner.left - rcDlg.right + rcDlg.left) / 2,
		rcOwner.top + (rcOwner.bottom - rcOwner.top - rcDlg.bottom + rcDlg.top) / 2,
		0, 0,
		SWP_NOSIZE);
}