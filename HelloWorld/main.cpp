
#include <ntddk.h>

NTSTATUS NtProcessStartup(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2
)
{
	UNREFERENCED_PARAMETER(kdmapperParam1);
	UNREFERENCED_PARAMETER(kdmapperParam2);
	
	DbgPrintEx(0, 0, "Hello world!");

	return 0;
}