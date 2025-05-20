#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>

#if defined(DISABLE_OUTPUT)
#define Log(content) 
#else
#define Log(content) std::wcout << content
#endif

namespace utils
{
	std::wstring GetFullTempPath();
	bool ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer);
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	bool DownloadFromUrl(const std::wstring& url, std::vector<uint8_t>* out_buffer);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
	BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
	uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	PVOID FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size);
	std::wstring GetCurrentAppFolder();
}