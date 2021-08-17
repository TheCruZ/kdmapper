#pragma once
#include <Windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"

#define PAGE_SIZE 0x1000

namespace kdmapper
{
	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr);

	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	uint64_t MapDriver(HANDLE iqvw64e_device_handle, BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, bool mdlMode = false, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr);
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
	uint64_t AllocMdlMemory(HANDLE iqvw64e_device_handle, uint64_t size, uint64_t* mdlPtr);
}