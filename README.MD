# KDMapper

Original creator https://github.com/z175

Updated and improved by https://github.com/TheCruZ

Mdl allocation writed by https://github.com/TygoL

Tested from **Windows 10 1607** to current **Windows 11 22449.1** :heavy_check_mark:

Update mainly done for UnknownCheats Forum https://www.unknowncheats.me/forum/members/1117395.html

KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory

**Note:** Add definition **DISABLE_OUTPUT** to remove all console outputs

## Features:
	
	Works with /GS- compiled drivers
	Hooks NtAddAtom which exists everywhere and is rarely called
	Clears MmUnloadedDrivers
	Clears PiDDBCacheTable
	Clears g_KernelHashBucketList
	Use NtLoadDriver and NtUnloadDriver for less traces
	Prevent load if \Device\Nal exists (Prevents BSOD)
	Header section skipped while copying driver to kernel
	Added param --free to automatically unmap the allocated memory
	Added param --mdl to map in mdl memory
	Added param --PassAllocationPtr to pass allocation ptr as first param
	Added the possibility to modify params before call driver entry
	Now you can pass directly bytes to mapdriver function
	
## Requirements:

    Set Custom Driver Entry Point
    Create a thread and return from driver entry fastest as you can to prevent unexpected calls

### Errors 0xC0000022 and 0xC000009A:
A lot of people ask me about this errors loading the vulnerable driver, both are caused by FACEIT AC since his driver is always running you have to uninstall it

Have Fun!!
