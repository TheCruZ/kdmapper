#pragma once

#include <string>
#include <vector>

struct SymNeeded {
	std::wstring binaryName;
	std::wstring symbolName;
};

//Require dbghelp.dll and symsrv.dll
class SimplestSymbolHandler {
public:

	SimplestSymbolHandler(std::wstring cachePath);

	~SimplestSymbolHandler();

	std::wstring GetPDB(const std::wstring binaryPath);

	std::vector<unsigned long long> GetOffset(std::wstring pdbPath, std::vector<std::wstring> symbolName);

private:
	unsigned long long process; //HANDLE but we don't want to share the windows.h include
};