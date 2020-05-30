#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

#include "nt.hpp"

namespace utils
{
	bool ReadFileToMemory(const std::string& file_path, std::vector<uint8_t>* out_buffer);
	bool CreateFileFromMemory(const std::string& desired_file_path, const char* address, size_t size);
	uint64_t GetKernelModuleAddress(const std::string& module_name);
}