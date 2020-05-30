#pragma once
#include <Windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

namespace nt
{
	constexpr auto PAGE_SIZE = 0x1000;
	constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

	constexpr auto SystemModuleInformation = 11;
	constexpr auto SystemHandleInformation = 16;
	constexpr auto SystemExtendedHandleInformation = 64;
	
	typedef struct _SYSTEM_HANDLE
	{
		PVOID Object;
		HANDLE UniqueProcessId;
		HANDLE HandleValue;
		ULONG GrantedAccess;
		USHORT CreatorBackTraceIndex;
		USHORT ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR HandleCount;
		ULONG_PTR Reserved;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	typedef enum _POOL_TYPE {
		NonPagedPool,
		NonPagedPoolExecute,
		PagedPool,
		NonPagedPoolMustSucceed,
		DontUseThisType,
		NonPagedPoolCacheAligned,
		PagedPoolCacheAligned,
		NonPagedPoolCacheAlignedMustS,
		MaxPoolType,
		NonPagedPoolBase,
		NonPagedPoolBaseMustSucceed,
		NonPagedPoolBaseCacheAligned,
		NonPagedPoolBaseCacheAlignedMustS,
		NonPagedPoolSession,
		PagedPoolSession,
		NonPagedPoolMustSucceedSession,
		DontUseThisTypeSession,
		NonPagedPoolCacheAlignedSession,
		PagedPoolCacheAlignedSession,
		NonPagedPoolCacheAlignedMustSSession,
		NonPagedPoolNx,
		NonPagedPoolNxCacheAligned,
		NonPagedPoolSessionNx
	} POOL_TYPE;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
}