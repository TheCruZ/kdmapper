#include "kdmapper.hpp"

HANDLE iqvw64e_device_handle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	if (argc != 2 && argc != 3) {
		Log(L"Usage: kdmapper.exe [--free] driver" << std::endl);
		return -1;
	}

	bool free = false;
	int drvIndex = 1;
	if (argc > 2) {
		if (_wcsicmp(argv[1], L"--free") == 0 || _wcsicmp(argv[1], L"/free") == 0) {
			free = true;
			drvIndex = 2;
		}
		else if (_wcsicmp(argv[2], L"--free") == 0 || _wcsicmp(argv[2], L"/free") == 0) {
			free = true;
		}
	}

	if (free) {
		Log(L"[+] Free pool memory after usage enabled" << std::endl);
	}

	if(std::filesystem::path(argv[drvIndex]).extension().string().compare(".sys") || argc == 3 && !free) {
		Log(L"Usage: kdmapper.exe [--free] driver" << std::endl);
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		return -1;
	}

	iqvw64e_device_handle = intel_driver::Load();

	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
		return -1;

	if (!kdmapper::MapDriver(iqvw64e_device_handle, driver_path, 0, 0, free, true)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	Log(L"[+] success" << std::endl);
}