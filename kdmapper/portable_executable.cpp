#include "portable_executable.hpp"

#include <Windows.h>
#include <string>


PIMAGE_NT_HEADERS64 portable_executable::GetNtHeaders(void* image_base) {
	const PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	const PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(image_base) + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return nt_headers;
}

portable_executable::vec_relocs portable_executable::GetRelocs(void* image_base) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	vec_relocs relocs;
	DWORD reloc_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	if (!reloc_va) //Fix from @greetmark of UnknownCheats Forum
		return {};

	ULONG64 ulong_image_base = reinterpret_cast<ULONG64>(image_base);
	PIMAGE_BASE_RELOCATION current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ulong_image_base + reloc_va);
	ULONG64 ulong_current_base_reloc = reinterpret_cast<ULONG64>(current_base_relocation);
	const PIMAGE_BASE_RELOCATION reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ulong_current_base_reloc + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	while (current_base_relocation < reloc_end && current_base_relocation->SizeOfBlock) {
		RelocInfo reloc_info;

		reloc_info.address = ulong_image_base + current_base_relocation->VirtualAddress;
		reloc_info.item = reinterpret_cast<USHORT*>(ulong_current_base_reloc + sizeof(IMAGE_BASE_RELOCATION));
		reloc_info.count = (current_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);

		relocs.push_back(reloc_info);

		current_base_relocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(ulong_current_base_reloc + current_base_relocation->SizeOfBlock);
	}

	return relocs;
}

portable_executable::vec_imports portable_executable::GetImports(void* image_base) {
	const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

	if (!nt_headers)
		return {};

	DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	//not imports necesary
	if (!import_va)
		return {};

	vec_imports imports;

	ULONG64 ulong_image_base = reinterpret_cast<ULONG64>(image_base);
	PIMAGE_IMPORT_DESCRIPTOR current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(ulong_image_base + import_va);

	while (current_import_descriptor->FirstThunk) {
		ImportInfo import_info;

		import_info.module_name = std::string(reinterpret_cast<char*>(ulong_image_base + current_import_descriptor->Name));

		PIMAGE_THUNK_DATA64 current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(ulong_image_base + current_import_descriptor->FirstThunk);
		PIMAGE_THUNK_DATA64 current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(ulong_image_base + current_import_descriptor->OriginalFirstThunk);

		while (current_originalFirstThunk->u1.Function) {
			ImportFunctionInfo import_function_data;

			PIMAGE_IMPORT_BY_NAME thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ulong_image_base + current_originalFirstThunk->u1.AddressOfData);

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
