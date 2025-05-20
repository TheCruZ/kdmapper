#include "utils.hpp"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <winhttp.h>
#include <string>
#include <filesystem>

#include "nt.hpp"

#pragma comment(lib, "winhttp.lib")

std::wstring utils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		Log(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool utils::ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer) {
	std::ifstream file_ifstream(file_path, std::ios::binary);

	if (!file_ifstream)
		return false;

	out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
	file_ifstream.close();

	return true;
}

bool utils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size)) {
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

uint64_t utils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH) {
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

BOOLEAN utils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t utils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	size_t max_len = dwLen - strlen(szMask);
	for (uintptr_t i = 0; i < max_len; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID utils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
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

std::wstring utils::GetCurrentAppFolder() {
	wchar_t buffer[1024];
	GetModuleFileNameW(NULL, buffer, 1024);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}

bool utils::DownloadFromUrl(const std::wstring& url, std::vector<uint8_t>* out_buffer) {
	HINTERNET hSession = WinHttpOpen(L"KDMapper/1.0", 
								   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
								   WINHTTP_NO_PROXY_NAME, 
								   WINHTTP_NO_PROXY_BYPASS, 
								   0);
	if (!hSession) {
		Log(L"[-] Failed to initialize WinHTTP session" << std::endl);
		return false;
	}

	// Parse URL
	URL_COMPONENTS urlComp;
	ZeroMemory(&urlComp, sizeof(urlComp));
	urlComp.dwStructSize = sizeof(urlComp);

	// Allocate memory for URL components
	wchar_t hostName[256] = { 0 };
	wchar_t urlPath[1024] = { 0 };
	wchar_t extraInfo[256] = { 0 };
	wchar_t scheme[32] = { 0 };

	urlComp.lpszHostName = hostName;
	urlComp.dwHostNameLength = sizeof(hostName) / sizeof(wchar_t);
	urlComp.lpszUrlPath = urlPath;
	urlComp.dwUrlPathLength = sizeof(urlPath) / sizeof(wchar_t);
	urlComp.lpszExtraInfo = extraInfo;
	urlComp.dwExtraInfoLength = sizeof(extraInfo) / sizeof(wchar_t);
	urlComp.lpszScheme = scheme;
	urlComp.dwSchemeLength = sizeof(scheme) / sizeof(wchar_t);

	if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
		Log(L"[-] Failed to parse URL. Error: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hSession);
		return false;
	}

	// Determine port and scheme
	INTERNET_PORT port = urlComp.nPort;
	DWORD flags = 0;
	
	if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
		flags = WINHTTP_FLAG_SECURE;
		if (port == 0) port = 443;
	} else if (port == 0) {
		port = INTERNET_DEFAULT_HTTP_PORT;
	}

	// Connect to server
	HINTERNET hConnect = WinHttpConnect(hSession, 
									  urlComp.lpszHostName,
									  port, 
									  0);
	if (!hConnect) {
		Log(L"[-] Failed to connect to server. Error: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hSession);
		return false;
	}

	// Create request
	HINTERNET hRequest = WinHttpOpenRequest(hConnect,
										  L"GET",
										  urlComp.lpszUrlPath,
										  NULL,
										  WINHTTP_NO_REFERER,
										  WINHTTP_DEFAULT_ACCEPT_TYPES,
										  flags);
	if (!hRequest) {
		Log(L"[-] Failed to create request. Error: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	// Send request
	if (!WinHttpSendRequest(hRequest,
						   WINHTTP_NO_ADDITIONAL_HEADERS,
						   0,
						   WINHTTP_NO_REQUEST_DATA,
						   0,
						   0,
						   0)) {
		Log(L"[-] Failed to send request. Error: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	// Receive response
	if (!WinHttpReceiveResponse(hRequest, NULL)) {
		Log(L"[-] Failed to receive response. Error: " << GetLastError() << std::endl);
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return false;
	}

	// Get response size
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	std::vector<uint8_t> buffer;

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
			Log(L"[-] Failed to query data size. Error: " << GetLastError() << std::endl);
			break;
		}

		if (dwSize == 0) break;

		size_t oldSize = buffer.size();
		buffer.resize(oldSize + dwSize);

		if (!WinHttpReadData(hRequest, 
						   buffer.data() + oldSize,
						   dwSize,
						   &dwDownloaded)) {
			Log(L"[-] Failed to read data. Error: " << GetLastError() << std::endl);
			break;
		}
	} while (dwSize > 0);

	// Cleanup
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);

	if (buffer.empty()) {
		Log(L"[-] No data downloaded" << std::endl);
		return false;
	}

	*out_buffer = std::move(buffer);
	return true;
}