#include "service.hpp"



bool service::RegisterAndStart(const std::string& driver_path)
{
	const std::string driver_name = std::filesystem::path(driver_path).filename().string();
	HKEY services,driver_service;
	LPCTSTR servicesPath = "SYSTEM\\CurrentControlSet\\Services";
	LSTATUS status = RegOpenKeyA(HKEY_LOCAL_MACHINE, servicesPath, &services);
	if (status != ERROR_SUCCESS)
	{
		printf("[-] Can't open services base registry key\n");
		return false;
	}

	status = RegOpenKeyA(services, driver_name.c_str(), &driver_service);
	if (status != ERROR_SUCCESS)
	{
		status = RegCreateKeyA(services, driver_name.c_str(), &driver_service);
	}

	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(services);
		RegCloseKey(driver_service);
		printf("[-] Can't open service registry key\n");
		return false;
	}

	status = RegSetKeyValueA(driver_service, NULL, "ImagePath", REG_EXPAND_SZ, ("\\??\\" + driver_path).c_str(), (DWORD)("\\??\\" + driver_path).size());
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(services);
		RegCloseKey(driver_service);
		printf("[-] Can't create 'ImagePath' registry value\n");
		return false;
	}
	DWORD data1 = 1;
	DWORD data3 = 3;
	status = RegSetKeyValueA(driver_service, NULL, "ErrorControl", REG_DWORD, &data1, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(services);
		RegCloseKey(driver_service);
		printf("[-] Can't create 'ErrorControl' registry value\n");
		return false;
	}

	status = RegSetKeyValueA(driver_service, NULL, "Start", REG_DWORD, &data3, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(services);
		RegCloseKey(driver_service);
		printf("[-] Can't create 'Start' registry value\n");
		return false;
	}

	status = RegSetKeyValueA(driver_service, NULL, "Type", REG_DWORD, &data1, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(services);
		RegCloseKey(driver_service);
		printf("[-] Can't create 'Type' registry value\n");
		return false;
	}
	
	RegCloseKey(services);
	RegCloseKey(driver_service);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return false;
	}
		

	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("[-] Can't get my process privileges token\n");
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;

	LUID luid;
	if (!LookupPrivilegeValue(NULL, "SeLoadDriverPrivilege", &luid))
	{
		printf("[-] Can't get my process privileges\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("[-] Can't set SeLoadDriverPrivilege\n");
		return false;
	}
	CloseHandle(hToken);

	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());
	
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	NTSTATUS st = NtLoadDriver(&serviceStr);
	printf("[+] NtLoadDriver Status 0x%lx\n", st);
	return st == 0;
}

bool service::StopAndRemove(const std::string& driver_name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());

	HKEY driver_service;
	std::string servicesPath = "SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	LSTATUS status = RegOpenKeyA(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS)
	{
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	printf("[+] NtUnloadDriver Status 0x%lx\n", st);
	if (st != 0x0) {
		printf("[-] Driver Unload Failed!!\n");
	}
	

	status = RegDeleteKeyA(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
	{
		return false;
	}
	return true;
}
