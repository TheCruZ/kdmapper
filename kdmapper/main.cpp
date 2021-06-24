#include "kdmapper.hpp"

HANDLE iqvw64e_device_handle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	
	std::cout << "[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << " by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl;
	
	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

int main(const int argc, char** argv)
{
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	if (argc != 2 && argc != 3) {
		std::cout << "Usage: kdmapper.exe [--free] driver" << std::endl;
		return -1;
	}

	bool free = false;
	int drvIndex = 1;
	if (argc > 2) {
		if (_stricmp(argv[1], "--free") == 0 || _stricmp(argv[1], "/free") == 0) {
			free = true;
			drvIndex = 2;
		}
		else if (_stricmp(argv[2], "--free") == 0 || _stricmp(argv[2], "/free") == 0) {
			free = true;
		}
	}

	if (free) {
		std::cout << "[+] Free pool memory after usage enabled" << std::endl;
	}

	if(std::filesystem::path(argv[drvIndex]).extension().string().compare(".sys") || argc == 3 && !free) {
		std::cout << "Usage: kdmapper.exe [--free] driver" << std::endl;
		return -1;
	}

	const std::string driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		std::cout << "[-] File " << driver_path << " doesn't exist" << std::endl;
		return -1;
	}

	iqvw64e_device_handle = intel_driver::Load();

	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
		return -1;

	if (!kdmapper::MapDriver(iqvw64e_device_handle, driver_path, 0, 0, free)) {
		std::cout << "[-] Failed to map " << driver_path << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << "[+] success" << std::endl;
}