# KDMapper

Original creator https://github.com/z175

Updated and improved by https://github.com/TheCruZ

PDB offsets parser written by https://github.com/Mohi-eddine

Independent Pages allocation written by https://github.com/Herooyyy/

Tested from **Windows 10 1607** to **Windows 11 26100.1882** :heavy_check_mark:

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
	Added param --indPages to map in allocated independent pages
	Added param --PassAllocationPtr to pass allocation ptr as first param
	Added the possibility to modify params before call driver entry
	Now you can pass bytes directly to mapdriver function
	Added PDB_OFFSETS macro that will allow the use of Offset PDB features (choose the target build or define in SymbolsHandler.hpp)
	Added param --OffsetsPath "FilePath" to include your own offsets file path (if FilePath contains spaces, it must be enclosed in quotation marks)
	Added param --DontUpdateOffset to execute without updating the offsets file (warning: you have to be sure that the offsets are not outdated to your current windows build, or you risk a potential BSOD)
	Introduced new project "SymbolsFromPDB" that will help KDMapper to adapt quickly to any windows updates by parsing the target .PDB files (PDB_OFFSETS macro must be defined to use this feature)
	
## Requirements:

    Return from driver entry fastest as you can to prevent unexpected calls or patch guard, don't ever create a infinite while loop in the driver entry, create a thread or any other procedure to keep code running (if you can't close kdmapper you are doing it wrong)
    Disable vulnerable driver list if enabled https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936

## Parameters
Just as reminder, in driver entry, **DriverObject and RegistryPath** are **NULL** unless you specify anything! this is a manual mapped driver and not a normal loading procedure

### Errors 0xC0000022 and 0xC000009A:
A lot of people ask me about this errors loading the vulnerable driver, both are caused by FACEIT AC since his driver is always running you have to uninstall it

### Error 0xC0000603:
The certificate has been blocked as vulnerable and the mapper will return a status of STATUS_IMAGE_CERT_REVOKED. More info at [Microsoft](https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936)

If you want to disable your vulnerable driver list you have to open regedit.exe, go to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config and set 'VulnerableDriverBlocklistEnable' as dword with value 0 and restart to apply the changes

Have Fun!!

#### TODO just maybe interesting ideas

if anyone interested in create a pull request

Self cleaning of self execution ?

* Registry User Assist
* Prefetch (need to be deleted normally after it's update)
* Recent files and AutomaticDestination
* Registry RecentDocs
* USN journal maybe?
* Self deletion option?
* Loaded driver deletion option?
* SRUM may contain any information?
* Shellbags in kdmapper named folders?

Messages for common loading errors?
