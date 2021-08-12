# KDMapper

Original creator https://github.com/z175

Updated and improved by https://github.com/TheCruZ

Tested from **Windows 10 1607** to current **Windows 11 22000** :heavy_check_mark:

Update mainly done for UnknownCheats Forum https://www.unknowncheats.me/forum/members/1117395.html

KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory

Note: Add definition DISABLE_OUTPUT to remove all console outputs

Fixups:

    Hook "NtQueryInformationAtom" which exists in all windows versions
    Fixed unable to load /GS- compiled drivers
	Update: Now hooks "NtAddAtom" which is 100x times less used than NtQueryInformationAtom
	Fixed 2 BSODs related to clear g_KernelHashBucketList and clear MmUnloadedDrivers

Improvements:

	Implemented NtLoadDriver and NtUnloadDriver for less traces
	Prevent load if \Device\Nal exists (Prevents BSOD)
	Automatic clear PiDDBCacheTable
	Header section skipped while copying driver to kernel
	Automatic clear g_KernelHashBucketList
	Added param --free to automatically free the allocated pool
	Added param --PassAllocationPtr to pass allocation ptr as first param
	
Requirements:

    Set Custom Driver Entry Point
    Create a thread and return from driver entry fastest as you can to prevent unexpected calls

Errors 0xC0000022 and 0xC000009A:

    Alot of people ask me about this errors loading the vulnerable driver, both are caused by FACEIT AC since his driver is always running you have to uninstall it

Have Fun!!
