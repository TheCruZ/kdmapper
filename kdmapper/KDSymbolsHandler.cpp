#ifdef PDB_OFFSETS

#include "KDSymbolsHandler.h"
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "utils.hpp"

bool KDSymbolsHandler::ReloadFile(std::wstring path, std::wstring updater) {
	symbols.clear();

	if (updater.empty() && !std::filesystem::exists(path) ||
		!updater.empty() && !std::filesystem::exists(updater)) {
		std::wcout << L"[-] Offsets file (" << path << L") or updater (" << updater << L") not found" << std::endl;
		return false;
	}

	if (!updater.empty()) {
		path = kdmUtils::GetCurrentAppFolder() + L"\\offsets.ini"; //default name if update is requested

		//delete old file
		std::filesystem::remove(path);

		std::wstring cmdW = L"\"" + updater + L"\"";
		auto exitCode = _wsystem(cmdW.c_str());
		if (exitCode != 0) {
			std::wcout << L"[-] Failed to update offsets" << std::endl;
			return false;
		}
	}

	//load file with ini format
	std::wifstream file(path);
	if (!file.is_open()) {
		std::wcout << L"[-] Failed to open offsets file" << std::endl;
		return false;
	}

	std::wstring line;
	std::wstring currentSection;

	while (std::getline(file, line)) {
		if (line.empty() || line[0] == L';' || line[0] == L'#') {
			continue;
		}
		if (line[0] == L'[') {
			currentSection = line.substr(1, line.size() - 2);
			continue;
		}
		auto pos = line.find(L'=');
		if (pos == std::wstring::npos) {
			continue;
		}
		auto name = line.substr(0, pos);
		auto offset = line.substr(pos + 1);
		symOffset sym{};
		sym.name = name;
		sym.offset = std::stoull(offset, nullptr, 10);
		std::wcout << L"[+] Loaded " << currentSection << L" - " << sym.name << L" - 0x" << std::hex << sym.offset << std::endl;
		symbols.push_back(sym);
	}

	std::wcout << L"[+] " << symbols.size() << L" Symbols Loaded" << std::endl;
	return true;
}

unsigned long long KDSymbolsHandler::GetOffset(std::wstring name) {
	for (auto sym : symbols) {
		if (sym.name == name) {
			return sym.offset;
		}
	}
	return 0;
}

#endif