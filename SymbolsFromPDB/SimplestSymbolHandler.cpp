#include "SimplestSymbolHandler.h"

#include <windows.h>
#include <string>
#include <memory>
#include <filesystem>
#include <iostream>
#include <dbghelp.h>
#pragma comment( lib, "dbghelp.lib" )


SimplestSymbolHandler::SimplestSymbolHandler(std::wstring cachePath) {
	process = (unsigned long long)GetCurrentProcess();
	SymInitializeW((HANDLE)process, (L"cache*" + cachePath + L";SRV*http://msdl.microsoft.com/download/symbols").c_str(), FALSE);
	SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_DEBUG);
}

SimplestSymbolHandler::~SimplestSymbolHandler() {
	SymCleanup((HANDLE)process);
}

std::wstring SimplestSymbolHandler::GetPDB(const std::wstring binaryPath) {

	SYMSRV_INDEX_INFOW info{};
	info.sizeofstruct = sizeof(SYMSRV_INDEX_INFOW);
	bool result = SymSrvGetFileIndexInfoW(binaryPath.c_str(), &info, 0);
	if (!result)
	{
		std::wcout << "[-] Failed to find binary info. Error: " << GetLastError() << std::endl;
		return {};
	}

	void* id;
	DWORD idType;
	if (info.guid == GUID{}) { // GUID is zeroed
		id = &info.sig;
		idType = SSRVOPT_DWORDPTR;
	}
	else {
		id = &info.guid;
		idType = SSRVOPT_GUIDPTR;
	}

	auto pdbPath = std::make_unique<wchar_t[]>(4096);
	bool found = SymFindFileInPathW(
		(HANDLE)process,
		NULL,
		info.pdbfile,
		id,
		info.age,
		0,
		idType,
		pdbPath.get(),
		NULL,
		NULL
	);

	auto resultPath = std::wstring(pdbPath.get());
	// Windows don't provide symsrv.dll and dbghelp loads it from his current path, if its not loaded after those calls means that symsrv/dbghelp are invalid
	if (resultPath.empty() && GetModuleHandleA("symsrv.dll") == nullptr) {
		std::wcout << "[-] Please provide proper dbghelp.dll and symsrv.dll!" << std::endl;
	}

	return resultPath;
}

std::vector<ULONG64> SimplestSymbolHandler::GetOffset(std::wstring pdbPath, std::vector<std::wstring> symbolName) {

	DWORD64 BaseAddr = 0x40000;
	DWORD FileSize = (DWORD)std::filesystem::file_size(pdbPath);

	// Load symbols for the module 
	std::wcout << "[+] Loading Symbols From " << pdbPath << std::endl;
	DWORD64 ModBase = SymLoadModuleExW(
		(HANDLE)process, // Process handle of the current process 
		NULL,                // Handle to the module's image file (not needed)
		pdbPath.c_str(),           // Path/name of the file 
		NULL,                // User-defined short name of the module (it can be NULL) 
		BaseAddr,            // Base address of the module (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		FileSize,            // Size of the file (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		NULL,
		NULL
	);

	if (ModBase == 0)
	{
		std::wcout << "[-] Error: SymLoadModule64() failed. Error code: " << GetLastError() << std::endl;
		return {};
	}


	SYMBOL_INFO_PACKAGEW SymInfoPackage{};
	SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFOW);
	SymInfoPackage.si.MaxNameLen = sizeof(SymInfoPackage.name);//MAX_SYM_NAME + 1;

	std::vector<ULONG64> offsets{};

	for (const auto& sym : symbolName) {
		BOOL bRet = SymFromNameW(
			(HANDLE)process,
			sym.c_str(),
			&SymInfoPackage.si
		);
		if (!bRet || !SymInfoPackage.si.Address)
		{
			std::wcout << "[-] Error: SymFromName() failed. Sym: " << sym << " || Error code: " << GetLastError() << std::endl;
			SymUnloadModule64(GetCurrentProcess(), ModBase);
			return {};
		}

		// Display information about the symbol 
		std::wcout << "[+] Symbol " << sym << " Offset: " << (DWORD)(SymInfoPackage.si.Address - ModBase) << std::endl;
		offsets.push_back((DWORD)(SymInfoPackage.si.Address - ModBase));
	}

	SymUnloadModule64(GetCurrentProcess(), ModBase);

	return offsets;
}