#include "service.hpp"


bool ExistOtherService(SC_HANDLE service_manager) {
	DWORD spaceNeeded = 0;
	DWORD numServices = 0;
	if (!EnumServicesStatus(service_manager, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &spaceNeeded, &numServices, 0) && GetLastError() != ERROR_MORE_DATA) {
		printf("[-] Can't enum service list error code: %d!!\n",GetLastError());
		return true;
	}
	spaceNeeded += sizeof(ENUM_SERVICE_STATUSA);
	LPENUM_SERVICE_STATUSA buffer = (LPENUM_SERVICE_STATUSA)new BYTE[spaceNeeded];

	if (EnumServicesStatus(service_manager, SERVICE_DRIVER, SERVICE_STATE_ALL, buffer, spaceNeeded, &spaceNeeded, &numServices, 0)) {
		for (DWORD i = 0; i < numServices; i++) {
			ENUM_SERVICE_STATUSA service = buffer[i];
			SC_HANDLE service_handle = OpenService(service_manager, service.lpServiceName, SERVICE_QUERY_CONFIG);
			if (service_handle) {
				LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)new BYTE[8096]; //8096 = max size of QUERY_SERVICE_CONFIGA
				DWORD needed = 0;
				if (QueryServiceConfig(service_handle, config, 8096, &needed)) {
					if (strstr(config->lpBinaryPathName, intel_driver::driver_name)) {
						delete[] buffer;
						printf("[-] WARNING: Service called '%s' have same file name!!\n", config->lpDisplayName);
						CloseServiceHandle(service_handle);
						return false;
					}
				}
				else {
					printf("[-] Note: Error query service %s error code: %d\n", service.lpServiceName, GetLastError());
				}
				CloseServiceHandle(service_handle);
			}
			
		}
		delete[] buffer;
		return false; //no equal services we can continue
	}
	delete[] buffer;
	printf("[-] Can't enum service list!!\n");
	return true;

}

bool ExistsValorantService(SC_HANDLE service_manager) {
	DWORD spaceNeeded = 0;
	DWORD numServices = 0;
	if (!EnumServicesStatus(service_manager, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &spaceNeeded, &numServices, 0) && GetLastError() != ERROR_MORE_DATA) {
		printf("[-] Can't enum service list error code: %d!!\n", GetLastError());
		return true;
	}
	spaceNeeded += sizeof(ENUM_SERVICE_STATUSA);
	LPENUM_SERVICE_STATUSA buffer = (LPENUM_SERVICE_STATUSA)new BYTE[spaceNeeded];

	if (EnumServicesStatus(service_manager, SERVICE_DRIVER, SERVICE_STATE_ALL, buffer, spaceNeeded, &spaceNeeded, &numServices, 0)) {
		for (DWORD i = 0; i < numServices; i++) {
			ENUM_SERVICE_STATUSA service = buffer[i];
			if (strstr(service.lpServiceName,"vgk")) {
				if ((service.ServiceStatus.dwCurrentState == SERVICE_RUNNING || service.ServiceStatus.dwCurrentState == SERVICE_START_PENDING)) {
					printf("[-] Valorant service running, kdmapper stopped to prevent BSOD!!\n");
					return true;
				}

			}
		}
		delete[] buffer;
		return false; //no valorant service found
	}
	delete[] buffer;
	printf("[-] Can't enum service list!!\n");
	return true;
}

bool service::RegisterAndStart(const std::string& driver_path)
{
	const std::string driver_name = std::filesystem::path(driver_path).filename().string();
	const SC_HANDLE sc_manager_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);

	if (!sc_manager_handle) {
		printf("[-] Can't open service manager\n");
		return false;
	}
	if (ExistOtherService(sc_manager_handle)) {
		return false;
	}

	if (ExistsValorantService(sc_manager_handle)) {
		return false;
	}

	SC_HANDLE service_handle = CreateService(sc_manager_handle, driver_name.c_str(), driver_name.c_str(), SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

	if (!service_handle)
	{
		service_handle = OpenService(sc_manager_handle, driver_name.c_str(), SERVICE_START);

		if (!service_handle)
		{
			printf("[-] Can't create the vulnerable service, check your AV!!\n");
			CloseServiceHandle(sc_manager_handle);
			return false;
		}
	}

	const bool result = StartService(service_handle, 0, nullptr);

	CloseServiceHandle(service_handle);
	CloseServiceHandle(sc_manager_handle);
	if (!result) {
		printf("[-] Can't start the vulnerable service, check your AV!!\n");
	}
	return result;
}

bool service::StopAndRemove(const std::string& driver_name)
{
	const SC_HANDLE sc_manager_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

	if (!sc_manager_handle)
		return false;

	const SC_HANDLE service_handle = OpenService(sc_manager_handle, driver_name.c_str(), SERVICE_STOP | DELETE);

	if (!service_handle)
	{
		CloseServiceHandle(sc_manager_handle);
		return false;
	}

	SERVICE_STATUS status = { 0 };
	const bool result = ControlService(service_handle, SERVICE_CONTROL_STOP, &status) && DeleteService(service_handle);

	CloseServiceHandle(service_handle);
	CloseServiceHandle(sc_manager_handle);

	return result;
}
