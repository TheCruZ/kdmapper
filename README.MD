# KDMapper

Original creator https://github.com/z175

Updated and improved by https://github.com/TheCruZ

Mdl allocation writed by https://github.com/TygoL

Independent Pages allocation written by https://github.com/Herooyyy/

Tested from **Windows 10 1607** to **Windows 11 22449.1** :heavy_check_mark:

Update mainly done for UnknownCheats Forum https://www.unknowncheats.me/forum/members/1117395.html

KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory

**Note:** Add definition **DISABLE_OUTPUT** to remove all console outputs

**Note:** Can be recommended like in the past set a custom entry point like in the HelloWorld example to reduce the generated code in the binary

## Features:
	
	Works with /GS- compiled drivers
	Hooks NtAddAtom which exists everywhere and is rarely called
	Clears MmUnloadedDrivers
	Clears PiDDBCacheTable
	Clears g_KernelHashBucketList
	Clears Wdfilter RuntimeDriverList RuntimeDriverCount and RuntimeDriverArry
	Use NtLoadDriver and NtUnloadDriver for less traces
	Prevent load if \Device\Nal exists (Prevents BSOD)
	Header section skipped while copying driver to kernel
	Added param --free to automatically unmap the allocated memory
	Added param --mdl to map in mdl memory
	Added param --indPages to map in allocated independent pages
	Added param --PassAllocationPtr to pass allocation ptr as first param
	Added the possibility to modify params before call driver entry
	Now you can pass directly bytes to mapdriver function
	
## Requirements:

    Return from driver entry fastest as you can to prevent unexpected calls or patch guard, don't ever create a infinite while loop in the driver entry, create a thread or any other procedure to keep code running (if you can't close kdmapper you are doing it wrong)
    Disable vulnerable driver list if enabled https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936

## Parameters
Just as reminder, in driver entry, **DriverObject and RegistryPath** are **NULL** unless you specify anything! this is a manual mapped driver and not a normal loading procedure

### Errors 0xC0000022 and 0xC000009A:
A lot of people ask me about this errors loading the vulnerable driver, both are caused by FACEIT AC since his driver is always running you have to uninstall it

### Error 0xC0000603:
The certificate has been blocked as vulnerable and the mapper will return a status of STATUS_IMAGE_CERT_REVOKED. More info at [Microsoft](https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936)

Have Fun!!
