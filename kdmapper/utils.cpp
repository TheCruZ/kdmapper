#include "utils.hpp"
#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <fstream>

#include "nt.hpp"

#pragma comment(lib, "winhttp.lib")

std::wstring kdmUtils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		kdmLog(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool kdmUtils::ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

bool kdmUtils::ReadUrlToMemory(const std::wstring& url, std::vector<BYTE>* out_buffer) {
	out_buffer->clear();
	DWORD statusCode = 0;
	DWORD statusCodeSize = sizeof(statusCode);

	URL_COMPONENTS urlComponents = {};
	urlComponents.dwStructSize = sizeof(urlComponents);

	wchar_t hostName[256] = {};
	wchar_t urlPath[2048] = {};
	wchar_t extraInfo[1024] = {};

	urlComponents.lpszHostName = hostName;
	urlComponents.dwHostNameLength = _countof(hostName);
	urlComponents.lpszUrlPath = urlPath;
	urlComponents.dwUrlPathLength = _countof(urlPath);
	urlComponents.lpszExtraInfo = extraInfo;
	urlComponents.dwExtraInfoLength = _countof(extraInfo);

	if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &urlComponents)) {
		kdmLog(L"[-] Invalid URL: " << url << std::endl);
		return false;
	}

	std::wstring host(hostName, urlComponents.dwHostNameLength);
	std::wstring path(urlPath, urlComponents.dwUrlPathLength);
	std::wstring query(extraInfo, urlComponents.dwExtraInfoLength);
	std::wstring object = path + query;
	if (object.empty()) {
		object = L"/";
	}

	if (urlComponents.nScheme != INTERNET_SCHEME_HTTP && urlComponents.nScheme != INTERNET_SCHEME_HTTPS) {
		kdmLog(L"[-] URL must use http or https" << std::endl);
		return false;
	}

	const bool useHttps = urlComponents.nScheme == INTERNET_SCHEME_HTTPS;

	HINTERNET hSession = WinHttpOpen(L"kdmapper/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession) {
		kdmLog(L"[-] WinHttpOpen failed: " << GetLastError() << std::endl);
		return false;
	}

	HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), urlComponents.nPort, 0);
	if (!hConnect) {
		kdmLog(L"[-] WinHttpConnect failed: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hSession);
		return false;
	}

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", object.c_str(),
		nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
		useHttps ? WINHTTP_FLAG_SECURE : 0);
	if (!hRequest) {
		kdmLog(L"[-] WinHttpOpenRequest failed: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	bool success = false;

	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
		WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		kdmLog(L"[-] WinHttpSendRequest failed: " << GetLastError() << std::endl);
		goto cleanup;
	}

	if (!WinHttpReceiveResponse(hRequest, nullptr)) {
		kdmLog(L"[-] WinHttpReceiveResponse failed: " << GetLastError() << std::endl);
		goto cleanup;
	}

	if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
		kdmLog(L"[-] WinHttpQueryHeaders failed: " << GetLastError() << std::endl);
		goto cleanup;
	}

	if (statusCode < 200 || statusCode >= 300) {
		kdmLog(L"[-] HTTP request failed with status " << statusCode << std::endl);
		goto cleanup;
	}

	for (;;) {
		DWORD availableSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &availableSize)) {
			kdmLog(L"[-] WinHttpQueryDataAvailable failed: " << GetLastError() << std::endl);
			goto cleanup;
		}

		if (availableSize == 0) {
			break;
		}

		const size_t previousSize = out_buffer->size();
		out_buffer->resize(previousSize + availableSize);

		DWORD downloadedSize = 0;
		if (!WinHttpReadData(hRequest, out_buffer->data() + previousSize, availableSize, &downloadedSize)) {
			kdmLog(L"[-] WinHttpReadData failed: " << GetLastError() << std::endl);
			goto cleanup;
		}

		out_buffer->resize(previousSize + downloadedSize);
	}

	success = !out_buffer->empty();

cleanup:
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return success;
}

bool kdmUtils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t kdmUtils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

BOOLEAN kdmUtils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t kdmUtils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID kdmUtils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	size_t namelength = strlen(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == strlen((char*)section->Name)) {
			if (!section->VirtualAddress) {
				return 0;
			}
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}
	return 0;
}

std::wstring kdmUtils::GetCurrentAppFolder() {
	wchar_t buffer[1024];
	GetModuleFileNameW(NULL, buffer, 1024);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}
