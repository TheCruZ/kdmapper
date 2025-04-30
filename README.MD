# KDMapper

KDMapper is a simple tool that exploits iqvw64e.sys Intel driver to manually map non-signed drivers in memory

Tested from **Windows 10 1607** to **Windows 11 24H2 26100.3775** :heavy_check_mark:

**Note:** Add definition **DISABLE_OUTPUT** to remove all console outputs

**Note:** Is recommended set a custom entry point like in the HelloWorld example


## Parameters:

	--copy-header to enable the copy driver header option by commandline
	--free to automatically unmap the allocated memory
	--indPages to map in allocated independent pages
	--PassAllocationPtr to pass allocation ptr as first param
	[PDB offset based build only]:
	--offsetsPath "FilePath" to include your own offsets file path (by default .\offsets.ini)(if FilePath contains spaces, it must be enclosed in quotation marks)
	--dontUpdateOffsets to execute without updating the offsets file (warning: you have to be sure that the offsets are not outdated to your current windows build, or you risk a potential BSOD)
	

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
	Added the possibility to modify params before call driver entry
	Added PDB_OFFSETS macro that will allow the use of Offset PDB features (choose the target build)
	Introduced new project "SymbolsFromPDB" that will help KDMapper to adapt quickly to any windows updates by parsing the target .PDB files (PDB_OFFSETS macro must be defined to use this feature)

## Building:

- Install Visual Studio: https://visualstudio.microsoft.com/downloads/
- Install Windows SDK: https://developer.microsoft.com/windows/downloads/windows-sdk/
- Install Windows WDK: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
- Open the solution
- Choose target build eg. Release
- Build

## Requirements:

- Return from driver entry fastest as you can to prevent unexpected calls or patch guard, don't ever create a infinite while loop in the driver entry, create a thread or any other procedure to keep code running (if you can't close kdmapper you are doing it wrong)
- Disable vulnerable driver list if enabled https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936

## Common issues

### BSOD with a simple driver
In DriverEntry, **DriverObject and RegistryPath** are **NULL** unless you specify anything! this is a manual mapped driver and **not a normal loading procedure**

### Error \\Device\\Nal is already in use.

This means that there is a intel driver already loaded or another instance of kdmapper is running or kdmapper crashed and didn't unload the previous driver.

If you are sure that there is no other instance of kdmapper running, you can try to restart your computer to fix this issue.

If the problem persists, you can try to unload the intel driver manually (If the driver was loaded with kdmapper will have a random name and will be located in %temp%), if not, the driver name is iqvw64e.sys and is installed with your network drivers.

### Errors 0xC0000022 and 0xC000009A:

Both are usually caused by FACEIT AC or other Antivirus/AntiCheat

**Note:** Some AntiCheats will keep running even if the game is not open

**Note:** Some Antivirus will keep blocking this even if you disabled them

### Error 0xC0000603:

The certificate has been blocked as vulnerable and the mapper will return a status of STATUS_IMAGE_CERT_REVOKED. More info at [Microsoft](https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936)

If you want to disable your vulnerable driver list you have to open regedit.exe, go to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Config and set 'VulnerableDriverBlocklistEnable' as dword with value 0 and restart to apply the changes
Alternativelty check this [Microsoft](https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936)

## Creators and contributors

Original creator https://github.com/z175

Updated and improved by https://github.com/TheCruZ

Initial PDB offsets parser written by https://github.com/Mohi-eddine

Independent Pages allocation written by https://github.com/Herooyyy/



Have Fun!!
