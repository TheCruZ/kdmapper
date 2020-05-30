#include "service.hpp"

bool service::RegisterAndStart(const std::string& driver_path)
{
	const std::string driver_name = std::filesystem::path(driver_path).filename().string();
	const SC_HANDLE sc_manager_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);

	if (!sc_manager_handle)
		return false;

	SC_HANDLE service_handle = CreateService(sc_manager_handle, driver_name.c_str(), driver_name.c_str(), SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

	if (!service_handle)
	{
		service_handle = OpenService(sc_manager_handle, driver_name.c_str(), SERVICE_START);

		if (!service_handle)
		{
			CloseServiceHandle(sc_manager_handle);
			return false;
		}
	}

	const bool result = StartService(service_handle, 0, nullptr);

	CloseServiceHandle(service_handle);
	CloseServiceHandle(sc_manager_handle);

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