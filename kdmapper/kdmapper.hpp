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
#define MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS 0x00000020  

namespace kdmapper
{
	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	uint64_t MapDriver(HANDLE iqvw64e_device_handle, const std::wstring& driver_path, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, bool PassAllocationAddressAsFirstParam);
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports);
}