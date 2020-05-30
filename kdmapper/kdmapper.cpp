#include "kdmapper.hpp"

uint64_t kdmapper::MapDriver(HANDLE iqvw64e_device_handle, const std::string& driver_path)
{
	std::vector<uint8_t> raw_image = { 0 };

	if (!utils::ReadFileToMemory(driver_path, &raw_image))
	{
		std::cout << "[-] Failed to read image to memory" << std::endl;
		return 0;
	}

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(raw_image.data());

	if (!nt_headers)
	{
		std::cout << "[-] Invalid format of PE image" << std::endl;
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::cout << "[-] Image is not 64 bit" << std::endl;
		return 0;
	}

	const uint32_t image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	uint64_t kernel_image_base = intel_driver::AllocatePool(iqvw64e_device_handle, nt::NonPagedPool, image_size);

	do
	{
		if (!kernel_image_base)
		{
			std::cout << "[-] Failed to allocate remote image in kernel" << std::endl;
			break;
		}

		std::cout << "[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl;

		// Copy image headers

		memcpy(local_image_base, raw_image.data(), nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
		{
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(raw_image.data()) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!ResolveImports(iqvw64e_device_handle, portable_executable::GetImports(local_image_base)))
		{
			std::cout << "[-] Failed to resolve imports" << std::endl;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(iqvw64e_device_handle, kernel_image_base, local_image_base, image_size))
		{
			std::cout << "[-] Failed to write local image to remote image" << std::endl;
			break;
		}

		VirtualFree(local_image_base, 0, MEM_RELEASE);

		// Call driver entry point

		const uint64_t address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		std::cout << "[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl;

		NTSTATUS status = 0;

		if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point))
		{
			std::cout << "[-] Failed to call driver entry" << std::endl;
			break;
		}

		std::cout << "[+] DriverEntry returned 0x" << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << status << std::nouppercase << std::dec << std::endl;

		// Erase PE headers

		intel_driver::SetMemory(iqvw64e_device_handle, kernel_image_base, 0, nt_headers->OptionalHeader.SizeOfHeaders);
		return kernel_image_base;

	} while (false);

	VirtualFree(local_image_base, 0, MEM_RELEASE);
	intel_driver::FreePool(iqvw64e_device_handle, kernel_image_base);

	return 0;
}

void kdmapper::RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta)
{
	for (const auto& current_reloc : relocs)
	{
		for (auto i = 0u; i < current_reloc.count; ++i)
		{
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				* reinterpret_cast<uint64_t*>(current_reloc.address + offset) += delta;
		}
	}
}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, portable_executable::vec_imports imports)
{
	for (const auto& current_import : imports)
	{
		if (!utils::GetKernelModuleAddress(current_import.module_name))
		{
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
			return false;
		}

		for (auto& current_function_data : current_import.function_datas)
		{
			const uint64_t function_address = intel_driver::GetKernelModuleExport(iqvw64e_device_handle, utils::GetKernelModuleAddress(current_import.module_name), current_function_data.name);

			if (!function_address)
			{
				std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
				return false;
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}