#pragma once
#include <Windows.h>
#include <stdint.h>
#include <vector>
#include <string>

namespace portable_executable
{
	struct RelocInfo
	{
		uint64_t address;
		uint16_t* item;
		uint32_t count;
	};

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	using vec_relocs = std::vector<RelocInfo>;
	using vec_imports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base);
	vec_relocs GetRelocs(void* image_base);
	vec_imports GetImports(void* image_base);
}