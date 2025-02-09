//TheCruZ Remake

#include <windows.h>

#include <vector>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>

#include "SimplestSymbolHandler.h"


std::wstring GetCurrentAppFolder() {
	wchar_t buffer[1024];
	GetModuleFileNameW(NULL, buffer, 1024);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}

int main()
{
	std::vector<std::wstring> targetBinaries = {
		L"C:\\Windows\\System32\\ntoskrnl.exe",
		L"C:\\Windows\\System32\\ci.dll"
	};

	if (std::filesystem::exists(L"C:\\Windows\\System32\\drivers\\WdFilter.sys")) {
		targetBinaries.push_back(L"C:\\Windows\\System32\\drivers\\WdFilter.sys");
	}
	else if (std::filesystem::exists(L"C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys")) {
		targetBinaries.push_back(L"C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys");
	}
	else {
		std::cout << "[-] Error: WdFilter.sys not found." << std::endl;
		return -1;
	}

	std::vector<SymNeeded> symbolsToRetrieve{
		{ L"ntoskrnl.exe", L"MmAllocateIndependentPagesEx" },
		{ L"ntoskrnl.exe", L"MmFreeIndependentPages" },
		{ L"ntoskrnl.exe", L"PiDDBLock" },
		{ L"ntoskrnl.exe", L"PiDDBCacheTable" },
		{ L"ntoskrnl.exe", L"MmSetPageProtection" },
		{ L"WdFilter.sys", L"MpBmDocOpenRules" },
		{ L"WdFilter.sys", L"MpFreeDriverInfoEx" },
		{ L"ci.dll", L"g_KernelHashBucketList" },
		{ L"ci.dll", L"g_HashCacheLock" },
	};

	SimplestSymbolHandler handler(GetCurrentAppFolder() + L"\\Symbols");

	for (const auto& binPath : targetBinaries) {
		auto pdbPath = handler.GetPDB(binPath);
		if (pdbPath.empty()) {
			std::wcout << L"[-] Failed to get symbol for " << binPath << std::endl;
			return -1;
		}

		std::vector<std::wstring> symbolsForThisFile{};
		for (const auto& sym : symbolsToRetrieve) {
			if (binPath.find(sym.binaryName) == std::wstring::npos) {
				continue;
			}
			symbolsForThisFile.push_back(sym.symbolName);
		}

		auto offsets = handler.GetOffset(pdbPath, symbolsForThisFile);
		if (offsets.size() != symbolsForThisFile.size()) {
			std::wcout << L"[-] Failed to get offsets for " << binPath << std::endl;
			return -1;
		}


		// Save as init format in offsets.ini
		std::wofstream ofs(GetCurrentAppFolder() + L"\\offsets.ini", std::ofstream::out | std::ofstream::app);
		if (!ofs.is_open()) {
			std::wcout << L"[-] Failed to open offsets.ini" << std::endl;
			return -1;
		}

		auto filename = std::filesystem::path(binPath).filename().wstring();

		ofs << L"[" << filename << L"]" << std::endl;
		for (size_t i = 0; i < symbolsForThisFile.size(); i++) {
			ofs << symbolsForThisFile[i] << L"=" << std::dec << offsets[i] << std::endl;
		}
		ofs << std::endl;
	}
	return 0;
}