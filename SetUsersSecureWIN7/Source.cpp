#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#include <windows.h>
#include <locale.h>
#include <lm.h>
#include <iostream>
#include <string>
#include <sddl.h>
#include "atlstr.h"
#include <ntsecapi.h> 
#include <conio.h>
using namespace std;


string name1, name2, comment;



LSA_HANDLE GetPolicyHandle(void)
{
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	LSA_HANDLE lsahPolicyHandle;

	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	NTSTATUS ntsResult = LsaOpenPolicy(
		NULL,
		&ObjectAttributes,
		POLICY_ALL_ACCESS,
		&lsahPolicyHandle
	);
	return lsahPolicyHandle;
}
PSID get_sid(LPWSTR user_name)
{
	SID Sid[128];
	WCHAR szDomain[1024];
	DWORD dwDomainSize = 1024;
	SID_NAME_USE SIDNameUse;
	DWORD dwLengthOfSID = 128;
		if (!LookupAccountName(NULL, user_name, Sid, &dwLengthOfSID, szDomain, &dwDomainSize, &SIDNameUse))
			printf("Error: %d\n", GetLastError());
		
		return Sid;

}
bool InitLsaString(PLSA_UNICODE_STRING pLsaString, LPCWSTR pwszString)
{
	DWORD dwLen = 0;

	if (NULL == pLsaString)
		return FALSE;

	if (NULL != pwszString)
	{
		dwLen = wcslen(pwszString);
		if (dwLen > 0x7ffe)   // String is too large
			return FALSE;
	}

	// Store the string.
	pLsaString->Buffer = (WCHAR *)pwszString;
	pLsaString->Length = (USHORT)dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength = (USHORT)(dwLen + 1) * sizeof(WCHAR);

	return TRUE;
}

int show_users()
{
	LPUSER_INFO_4 *pTmpBuf1 = NULL;
	DWORD dwlevel = 0;
	DWORD dwfilter = 0;
	USER_INFO_0 * theEntries = NULL;
	DWORD dwprefmaxlen = 512;
	DWORD dwentriesread;
	DWORD dwtotalentries;
	NET_API_STATUS nStatus = NetUserEnum(NULL, dwlevel, dwfilter, (LPBYTE*)&theEntries, dwprefmaxlen, &dwentriesread, &dwtotalentries, NULL);

	if (nStatus != NERR_Success)
	{
		cout << "ERROR: NetUserEnum();" << endl;
		return -1;
	}

	cout << "Users:" << endl << endl;
	for (int i = 0; i < dwentriesread; ++i)
	{
		SID Sid[128];
		WCHAR szDomain[1024];
		DWORD dwDomainSize = 1024;
		SID_NAME_USE SIDNameUse;
		DWORD dwLengthOfSID = 128;
		LPTSTR sidString;
		if (!LookupAccountName(NULL, theEntries[i].usri0_name, Sid, &dwLengthOfSID, szDomain, &dwDomainSize, &SIDNameUse))
			printf("Error: %d\n", GetLastError());
		if (!ConvertSidToStringSid(Sid, &sidString)) {
			return GetLastError();
		}
		wprintf(L"%s (%s)\n", theEntries[i].usri0_name, sidString);
		cout << "Привилегии: ";
		LSA_OBJECT_ATTRIBUTES ObjectAttributes;
		LSA_HANDLE lsahPolicyHandle;

		ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

		NTSTATUS ntsResult = LsaOpenPolicy(
			NULL,
			&ObjectAttributes,
			POLICY_LOOKUP_NAMES,
			&lsahPolicyHandle
		);
		PLSA_UNICODE_STRING rights;
		ULONG count = 0;
		nStatus = LsaEnumerateAccountRights(lsahPolicyHandle, Sid, &rights, &count);
		//printf("Error: %d\n", GetLastError());
		if (nStatus == ERROR_SUCCESS)
		{
			for (int i = 0; i < count - 1; i++, rights++)			
				wprintf(L"%s, ", rights->Buffer);
			wprintf(L"%s.\n\n", rights->Buffer);
		}
		else
			cout << "none" << endl << endl;
		
	}
	

	return 0;
}

int show_group()
{
	LOCALGROUP_INFO_0 *pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;

	NET_API_STATUS nStatus = NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);

	if (nStatus != NERR_Success)
	{
		cout << "ERROR: NetLocalGroupEnum();" << endl;
		return -1;
	}

	cout << "Группы:" << endl;
	for (DWORD i = 0; i < dwEntriesRead; i++) {
		wprintf(L"\n%s\n", pBuf[i].lgrpi0_name);
		cout << "Привилегии: ";
		LPTSTR sidString;
		SID Sid[128];
		WCHAR szDomain[1024];
		DWORD dwDomainSize = 1024;
		SID_NAME_USE SIDNameUse;
		DWORD dwLengthOfSID = 128;
		if (!LookupAccountName(NULL, pBuf[i].lgrpi0_name, Sid, &dwLengthOfSID, szDomain, &dwDomainSize, &SIDNameUse))
			printf("Error: %d\n", GetLastError());
		PLSA_UNICODE_STRING rights;
		ULONG count = 0;
		nStatus = LsaEnumerateAccountRights(GetPolicyHandle(), Sid, &rights, &count);
		//printf("Error: %d\n", GetLastError());
		if (nStatus == ERROR_SUCCESS)
		{
			for (int i = 0; i < count - 1; i++, rights++)
				wprintf(L"%s, ", rights->Buffer);
			wprintf(L"%s.\n\n", rights->Buffer);
		}
		else
			cout << "none" << endl << endl;

	}

	return 0;
}

int add_user(LPWSTR name, LPWSTR pass, int priv)
{
	USER_INFO_1 ui;
	ui.usri1_name = name;
	ui.usri1_password = pass;
	if (priv == 1)
		ui.usri1_priv = USER_PRIV_GUEST;
	else if (priv == 2)
		ui.usri1_priv = USER_PRIV_USER;
	else if (priv == 3)
		ui.usri1_priv = USER_PRIV_ADMIN;
	ui.usri1_home_dir = NULL;
	ui.usri1_comment = NULL;
	ui.usri1_flags = UF_SCRIPT;
	ui.usri1_script_path = NULL;
	NET_API_STATUS nStatus = NetUserAdd(NULL,/*NULL - создается локально*/1, (LPBYTE)&ui, 0);
	
	if (nStatus == NERR_Success)
	{
		cout << "Пользователь успешно создан" << endl;
	}
	else
	{
		cout << "Во время создания аккаунта произошла ошибка" << endl;
		return -1;
	}

	return 0;
}

int set_privilege(LPWSTR name, char* priv, int flag)
{
	LPTSTR sidString;
	PSID sid = get_sid(name);
	
	if (!ConvertSidToStringSid(sid, &sidString)) {
		return GetLastError();
	}
	wprintf(L"(%s)\n", sidString);
	NTSTATUS ntsResult;
	LSA_UNICODE_STRING UserRights;
	ULONG CountOfRights = 1;

	wchar_t* wc_priv = new wchar_t[strlen(priv) + 1];
	mbstowcs_s(NULL, wc_priv, strlen(priv) + 1, priv, strlen(priv));

	if (!InitLsaString(&UserRights, wc_priv))
		wprintf(L"Error: InitLsaString();\n");
	if (flag == 1)
		ntsResult = LsaAddAccountRights(GetPolicyHandle(), sid, &UserRights, 1);
	else
		ntsResult = LsaRemoveAccountRights(GetPolicyHandle(), sid, FALSE, &UserRights, 1);
    if ((ntsResult == 0))
	{
		if (flag == 1)
			cout << "Привилегия добавлена." << endl;
		else 
			cout << "Привилегия удалена." << endl;
	}
	else {
		printf("Error: %d\n", LsaNtStatusToWinError(ntsResult));
		cout << "Error: LsaAddAccountRights() or LsaRemoveAccountRights(); :: " << LsaNtStatusToWinError(ntsResult) << endl;
		
	}
	return 0;
}


int main()
{
	string enter;
	setlocale(LC_CTYPE, "rus");
	//SetConsoleCP(1251);
//SetConsoleOutputCP(1251);

	while (1)
	{
		cout << ">> ";

		getline(cin, enter);
		system("cls");
		if (enter == "show users")
			show_users();
		else if (enter == "show groups")
			show_group();
		else if (enter == "set group priv")
		{
			int flag = 1;
			int c;
			cout << "Введите имя локальной группы: ";
			getline(cin, name1);
			cout << "Выберите, что сделать с привилегией:\n1. Добавить\n2. Удалить\n";
			(cin >> c).get();
			switch (c)
			{
			case 1:
				flag = 1;
				break;
			case 2:
				flag = 0;
				break;
			default:
				break;
			}
			cout << "Введите право, которое хотите добавить/удалить: ";
			getline(cin, name2);
			CA2W name1_unc(name1.c_str(), 1250);
            set_privilege(name1_unc, (char*)name2.c_str(), flag);
		}
		else if (enter == "delete group")
		{
			cout << "Введите имя локальной группы: ";
			getline(cin, name1);
			CA2W name1_unc(name1.c_str(), 1250);
			NET_API_STATUS nStatus = NetLocalGroupDel(NULL, name1_unc);

			if (nStatus == NERR_Success)
				cout << "Локальная группа успешно удалена" << endl;
			else
			    cout << "Error: NetLocalGroupDel();" << endl;
				
		}
		else if (enter == "add group")
		{
			cout << "Введите имя группы: ";
			getline(cin, name1);
			CA2W name1_unc(name1.c_str(), 1250);
			LOCALGROUP_INFO_0 pBuf;
			pBuf.lgrpi0_name = name1_unc;
			NET_API_STATUS nStatus = NetLocalGroupAdd(NULL, 0, (LPBYTE)&pBuf, 0);

			if (nStatus == NERR_Success)
				cout << "Группа успешно создана" << endl;
			else
				cout << "Error: NetLocalGroupAdd();" << endl;
			
		}
		else if (enter == "add user to group")
		{
			cout << "Введите имя группы: ";
			getline(cin, name1);
			cout << "Введите имя пользователя: ";
			getline(cin, name2);
			CA2W name1_unc(name1.c_str(), 1250);
			CA2W name2_unc(name2.c_str(), 1250);
			LOCALGROUP_MEMBERS_INFO_3 pBuf;
			pBuf.lgrmi3_domainandname = name2_unc;
			NET_API_STATUS nStatus = NetLocalGroupAddMembers(NULL, name1_unc, 3, (LPBYTE)&pBuf, 1);
			if (nStatus == NERR_Success)
				cout << "Пользователь успешно добавлен в группу" << endl;
			else 
				cout << "Error: NetLocalGroupAddMembers()" << endl;
		}
		else if (enter == "delete user from group")
		{
			cout << "Введите имя группы: ";
			getline(cin, name1);
			cout << "Введите имя пользователя: ";
			getline(cin, name2);
			CA2W name1_unc(name1.c_str(), 1250);
			CA2W name2_unc(name2.c_str(), 1250);
			LOCALGROUP_MEMBERS_INFO_3 pBuf;
			pBuf.lgrmi3_domainandname = name2_unc;
			NET_API_STATUS	nStatus = NetLocalGroupDelMembers(NULL, name1_unc, 3, (LPBYTE)&pBuf, 1);
		
			if (nStatus == NERR_Success)
				cout << "Пользователь успешно удален из группы." << endl;
			else
				cout << "Error: NetLocalGroupDelMembers();" << endl;

		}
		else if (enter == "add user")
		{
			string pass;
			int c;
			cout << "Введите имя пользователя: ";
			getline(cin, name1);
			cout << "Введите пароль пользователя: ";
			getline(cin, pass);
			cout << "Выберите тип привилегий:\n1. Гостевой\n2. Пользовательский\n3. Администраторский\n";
			(cin >> c).get();
			CA2W name_unc(name1.c_str(), 1250);
			CA2W pass_unc(pass.c_str(), 1250);
			switch (c)
			{
			case 1:
				add_user(name_unc, pass_unc, 1);
				break;
			case 2:
				add_user(name_unc, pass_unc, 2);
				break;
			case 3:
				add_user(name_unc, pass_unc, 3);
				break;
			default:
				break;
			}
		}
		else if (enter == "delete user")
		{
			cout << "Введите имя пользователя: ";
			getline(cin, name1);
			CA2W name1_unc(name1.c_str(), 1250);
			NET_API_STATUS nStatus;
			nStatus = NetUserDel(NULL, name1_unc);
			if (nStatus == NERR_Success)
				cout << "Пользователь успешно удален" << endl;
			else 
				cout << "Во время создания аккаунта произошла ошибка" << endl;
			
		}
		else if (enter == "set user priv")
		{
			string pass;
			int c, z, flag = 0;
			cout << "Введите имя пользователя: ";
			getline(cin, name1);
			cout << "Выберите, что сделать с привилегией:\n1. Добавить\n2. Удалить\n";
			(cin >> z).get();
			switch (z)
			{
			case 1:
				flag = 1;
				break;
			case 2:
				flag = 0;
				break;
			default:
				break;
			}
			cout << "Введите право, которое хотите добавить/удалить: ";
			getline(cin, name2);
			CA2W name1_unc(name1.c_str(), 1250);
			set_privilege(name1_unc, (char*)name2.c_str(), flag);
		
		}
		else if (enter == "help")
			cout << "                        HELP:\n\n\
			show users - Вывести список пользователей.\n\
add user - Добавить пользователя.\n\
delete user - Удалить пользователя.\n\
set user priv - Изменить пользователя.\n\
show groups - Вывести список групп.\n\
set group priv - Изменить группу.\n\
add group - Добавить группу.\n\
delete group - Удалить группу.\n\
add user to group - Добавить пользователя в группу.\n\
delete user from group - Удалить пользователя из группы.\n\
end - Выйти.\n\n\
Нажмите любую клавишу для выхода из помощи..." << endl;
		else if (enter == "end")
		    return 0;
		else
			cout << "Некорректная команда" << endl;

		_getch();
		system("cls");

	}
}
