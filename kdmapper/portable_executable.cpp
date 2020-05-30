#include "portable_executable.hpp"

PIMAGE_NT_HEADERS64 portable_executable::GetNtHeaders(void* image_base)
{
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(image_base) + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return nt_headers;
}

portable_executable::vec_relocs portable_executable::GetRelocs(void* image_base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	vec_relocs relocs;

	auto current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	const auto reloc_end = reinterpret_cast<uint64_t>(current_base_relocation) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	while (current_base_relocation->VirtualAddress && current_base_relocation->VirtualAddress < reloc_end && current_base_relocation->SizeOfBlock)
	{
		RelocInfo reloc_info;

		reloc_info.address = reinterpret_cast<uint64_t>(image_base) + current_base_relocation->VirtualAddress;
		reloc_info.item = reinterpret_cast<uint16_t*>(reinterpret_cast<uint64_t>(current_base_relocation) + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

		relocs.push_back(reloc_info);

		current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint64_t>(current_base_relocation) + current_base_relocation->SizeOfBlock);
	}

	return relocs;
}

portable_executable::vec_imports portable_executable::GetImports(void* image_base)
{
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	vec_imports imports;

	auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(image_base) + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (current_import_descriptor->FirstThunk)
	{
		ImportInfo import_info;

		import_info.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->Name));

		auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->FirstThunk);
		auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function)
		{
			ImportFunctionInfo import_function_data;

			auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(image_base) + current_originalFirstThunk->u1.AddressOfData);

			import_function_data.name = thunk_data->Name;
			import_function_data.address = &current_first_thunk->u1.Function;

			import_info.function_datas.push_back(import_function_data);

			++current_originalFirstThunk;
			++current_first_thunk;
		}

		imports.push_back(import_info);
		++current_import_descriptor;
	}

	return imports;
}