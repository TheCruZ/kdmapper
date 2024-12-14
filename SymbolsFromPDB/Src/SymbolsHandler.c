#include "SymbolsHandler.h"

BOOLEAN GenerateOffsetFile()
{
	SYM_INFO NtOsKernelFunctionsInfo[] = {
		{NULL,"MmAllocateIndependentPagesEx",0,0 },
		{NULL,"MmFreeIndependentPages",0,0 },
		{NULL,"PiDDBLock",0,0 },
		{NULL,"PiDDBCacheTable",0,0 },
		{NULL,"MmSetPageProtection",0,0 },
		//Keep Adding Here
	};
	
	SYM_INFO WdFilterFunctionsInfo[] = {
		{NULL,"MpBmDocOpenRules",0,0 },
		{NULL,"MpFreeDriverInfoEx",0,0 },
		//Keep Adding Here
	};

	SYM_INFO CIFunctionsInfo[] = {
		{NULL,"g_KernelHashBucketList",0,0 },
		{NULL,"g_HashCacheLock",0,0 },
		//Keep Adding Here
	};

	SYMBOLS_DATA SymsData[] = {
		{NTOSKRNL_PATH	,NtOsKernelFunctionsInfo	,Elements_Count(NtOsKernelFunctionsInfo,SYM_INFO)	},
		{WDFILTER_PATH	,WdFilterFunctionsInfo		,Elements_Count(WdFilterFunctionsInfo,SYM_INFO)		},
		{CIDLL_PATH		,CIFunctionsInfo			,Elements_Count(CIFunctionsInfo,SYM_INFO)			},
	};

	for(int FunctionsInfoIdx = 0 ; FunctionsInfoIdx < Elements_Count(SymsData, SYMBOLS_DATA) ;++FunctionsInfoIdx)
	{
		printf("\n");
		if (!InitKernelSymbolsList(SymsData[FunctionsInfoIdx].PDBFileName, &SymsData[FunctionsInfoIdx].SymbolsInfoArray))
		{
			printf("Error: Failed To Get One Or More Function Offset.\n");
			return FALSE;
		}
	}

	HANDLE File = CreateFileA(FUNCOFFSET_PATH, GENERIC_WRITE, FILE_SHARE_READ,
		NULL, CREATE_ALWAYS, 0, NULL);

	if (!File || File == INVALID_HANDLE_VALUE)
	{
		printf("Error: Failed To Create Symbols Offset File.\n");
		return FALSE;
	}

	PBYTE Buffer = NULL;
	SIZE_T OffsetSize = 2 + sizeof(SymsData->SymbolsInfoArray.SymbolsArray->SymbolOffset) * 2;

	SIZE_T BufferSize = 0;
	DWORD BufferOffset = 0;

	for (int FunctionsInfoIdx = 0; FunctionsInfoIdx < Elements_Count(SymsData, SYMBOLS_DATA); ++FunctionsInfoIdx)
	{
		//counting number of bytes
		SIZE_T BytesCount = 0;
		for (int FunctionIdx = 0; FunctionIdx < SymsData[FunctionsInfoIdx].SymbolsInfoArray.ElementsCount; ++FunctionIdx)
		{
			BytesCount += SymsData[FunctionsInfoIdx].SymbolsInfoArray.SymbolsArray[FunctionIdx].NameLen;
			BytesCount += OffsetSize;
			BytesCount += 2;//for '\n' and ','
		}
		BufferSize += BytesCount;
	}

	if (!BufferSize)
	{
		printf("Error: Failed To Get File Buffer Size.\n");
		goto FailExit;
	}

	Buffer = malloc(BufferSize);
	if (!Buffer)
	{
		printf("Error: Failed To Allocate Memory For File Buffer.\n");
		goto FailExit;
	}
	
	for (int FunctionsInfoIdx = 0; FunctionsInfoIdx < Elements_Count(SymsData, SYMBOLS_DATA); ++FunctionsInfoIdx)
	{
		//writing data
		for (int FunctionIdx = 0; FunctionIdx < SymsData[FunctionsInfoIdx].SymbolsInfoArray.ElementsCount; ++FunctionIdx)
		{
			memcpy(Buffer + BufferOffset, SymsData[FunctionsInfoIdx].SymbolsInfoArray.SymbolsArray[FunctionIdx].SymbolName, SymsData[FunctionsInfoIdx].SymbolsInfoArray.SymbolsArray[FunctionIdx].NameLen);
			BufferOffset += SymsData[FunctionsInfoIdx].SymbolsInfoArray.SymbolsArray[FunctionIdx].NameLen;

			*(Buffer + BufferOffset) = ',';
			++BufferOffset;

			snprintf((Buffer + BufferOffset), (size_t)(1 + OffsetSize), "0x%08X", SymsData[FunctionsInfoIdx].SymbolsInfoArray.SymbolsArray[FunctionIdx].SymbolOffset);//+1 for  NULL terminator 
			BufferOffset += OffsetSize;

			*(Buffer + BufferOffset) = '\n';
			++BufferOffset;
		}
	}

	BOOL IsWritten = WriteFile(
		File,
		Buffer,
		BufferSize,
		NULL,
		NULL);

	CloseHandle(File);
	free(Buffer);

	if (!IsWritten)
	{
		printf("Error: Failed To Write To Symbols Offset File.\n");
		return FALSE;
	}
	return TRUE;

FailExit:
	CloseHandle(File);
	return FALSE;
}

BOOLEAN InitKernelSymbolsList(
	IN const CHAR* FilePath,
	IN OUT PSYM_INFO_ARRAY pSymbolsArray)
{
	if (!FilePath || !pSymbolsArray)
		return FALSE;

	BOOL bRet = FALSE;
	BOOL Result = TRUE;

	// Set options 

	DWORD Options = SymGetOptions();

	// SYMOPT_DEBUG option asks DbgHelp to print additional troubleshooting 
	// messages to debug output - use the debugger's Debug Output window 
	// to view the messages 

	Options |= SYMOPT_DEBUG;

	SymSetOptions(Options);

	// Initialize DbgHelp and load symbols for all modules of the current process 

	bRet = SymInitialize(
		GetCurrentProcess(),  // Process handle of the current process 
		NULL,                 // No user-defined search path -> use default 
		FALSE                 // Do not load symbols for modules in the current process 
	);

	if (!bRet)
	{
		printf("Error: SymInitialize() failed. Error code: %u \n", GetLastError());
		return 0;
	}

	do
	{
		// Determine the base address and the file size 

		const CHAR* pFileName = FilePath;

		DWORD64   BaseAddr = 0;
		DWORD     FileSize = 0;

		if (!GetFileParams(pFileName, &BaseAddr, &FileSize))
		{
			printf(("Error: Cannot obtain file parameters (internal error).\n"));
			Result = FALSE;
			break;
		}


		// Load symbols for the module 
		printf("-> Loading Symbols From %s ... \n",pFileName);
		DWORD64 ModBase = SymLoadModule64(
			GetCurrentProcess(), // Process handle of the current process 
			NULL,                // Handle to the module's image file (not needed)
			pFileName,           // Path/name of the file 
			NULL,                // User-defined short name of the module (it can be NULL) 
			BaseAddr,            // Base address of the module (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
			FileSize             // Size of the file (cannot be NULL if .PDB file is used, otherwise it can be NULL) 
		);

		if (ModBase == 0)
		{
			printf("Error: SymLoadModule64() failed. Error code: %u \n", GetLastError());
			Result = FALSE;
			break;
		}

#ifndef NDEBUG
		printf("Load address: %I64x \n", ModBase);
#endif

		// Obtain and display information about loaded symbols 
#ifndef NDEBUG
		ShowSymbolInfo(ModBase);
#endif

		SYMBOL_INFO_PACKAGE SymInfoPackage = { NULL };
		SymInfoPackage.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		SymInfoPackage.si.MaxNameLen = sizeof(SymInfoPackage.name);//MAX_SYM_NAME + 1;
		// space for the name of the symbol 
		for (int i = 0; i < pSymbolsArray->ElementsCount; ++i)
		{
			PCSTR SymName = pSymbolsArray->SymbolsArray[i].SymbolName;
			bRet = SymFromName(
				GetCurrentProcess(), // Process handle of the current process 
				SymName,             // Symbol name 
				&SymInfoPackage.si   // Address of the SYMBOL_INFO structure (inside "sip" object) 
			);

			if (!bRet || !SymInfoPackage.si.Address)
			{
				printf("Error: SymFromName() failed. Sym: %s || Error code: %u \n", pSymbolsArray->SymbolsArray[i].SymbolName, GetLastError());
				Result = FALSE;
			}
			else
			{
				// Display information about the symbol 
				pSymbolsArray->SymbolsArray[i].SymbolOffset = (DWORD)(SymInfoPackage.si.Address - ModBase);
				pSymbolsArray->SymbolsArray[i].NameLen = SymInfoPackage.si.NameLen;
				printf("Symbol %s Offset: %X\n", SymName, pSymbolsArray->SymbolsArray[i].SymbolOffset);

				//ShowSymbolDetails(sip.si);
			}

		}
		// Unload symbols for the module 

		bRet = SymUnloadModule64(GetCurrentProcess(), ModBase);

		if (!bRet)
		{
			printf("Error: Unload Symbols failed. Error code: %u \n", GetLastError());
		}

	} while (0);


	// Deinitialize DbgHelp 

	bRet = SymCleanup(GetCurrentProcess());

	if (!bRet)
	{
		printf("Error: Sym Cleanup failed. Error code: %u \n", GetLastError());
		return 0;
	}


	// Complete 

	return Result;
}


///////////////////////////////////////////////////////////////////////////////
// Functions 
//

BOOLEAN GetFileParams(IN
	const CHAR* pFileName,
	OUT uintptr_t* BaseAddr,
	OUT DWORD* FileSize)
{
	// Check parameters 

	if (!pFileName || !BaseAddr || !FileSize)
	{
		return FALSE;
	}


	// Determine the extension of the file 

	CHAR szFileExt[_MAX_EXT] = { 0 };

	_splitpath_s(pFileName, NULL, 0, NULL, 0, NULL, 0, szFileExt, _MAX_EXT);


	// Is it .PDB file ? 

	if (_stricmp(szFileExt, ".PDB") == 0)
	{
		// Yes, it is a .PDB file 

		// Determine its size, and use a dummy base address 

		*BaseAddr = 0x10000000; // it can be any non-zero value, but if we load symbols 
		// from more than one file, memory regions specified 
		// for different files should not overlap 
		// (region is "base address + file size") 

		if (!_GetFileSize(pFileName, FileSize))
		{
			return FALSE;
		}

	}
	else
	{
		// It is not a .PDB file 

		// Base address and file size can be 0 

		*BaseAddr = 0;
		*FileSize = 0;
		return FALSE;
	}


	// Complete 

	return TRUE;

}

BOOLEAN _GetFileSize(
	IN const CHAR* pFileName,
	OUT DWORD* FileSize)
{
	// Check parameters 

	if (!pFileName || !FileSize)
	{
		return FALSE;
	}


	// Open the file 

	HANDLE hFile = CreateFileA(pFileName, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile() failed. Error: %u \n", GetLastError());
		return FALSE;
	}


	// Obtain the size of the file 

	*FileSize = GetFileSize(hFile, NULL);

	if (*FileSize == INVALID_FILE_SIZE)
	{
		printf("GetFileSize() failed. Error: %u \n", GetLastError());
		// and continue ... 
	}


	// Close the file 

	if (!CloseHandle(hFile))
	{
		printf("CloseHandle() failed. Error: %u \n", GetLastError());
		// and continue ... 
	}


	// Complete 

	return (*FileSize != INVALID_FILE_SIZE);

}

#ifndef NDEBUG
void ShowSymbolInfo(
	IN uintptr_t ModBase)
{
	// Get module information 

	IMAGEHLP_MODULE ModuleInfo;

	memset(&ModuleInfo, 0, sizeof(ModuleInfo));

	ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);

	BOOL bRet = SymGetModuleInfo64(GetCurrentProcess(), ModBase, &ModuleInfo);

	if (!bRet)
	{
		printf("Error: SymGetModuleInfo64() failed. Error code: %u \n", GetLastError());
		return;
	}


	// Display information about symbols 

		// Kind of symbols 

	switch (ModuleInfo.SymType)
	{
	case SymNone:
		printf("No symbols available for the module.\n");
		break;

	case SymExport:
		printf("Loaded symbols: Exports\n");
		break;

	case SymCoff:
		printf("Loaded symbols: COFF\n");
		break;

	case SymCv:
		printf("Loaded symbols: CodeView\n");
		break;

	case SymSym:
		printf("Loaded symbols: SYM\n");
		break;

	case SymVirtual:
		printf("Loaded symbols: Virtual\n");
		break;

	case SymPdb:
		printf("Loaded symbols: PDB\n");
		break;

	case SymDia:
		printf("Loaded symbols: DIA\n");
		break;

	case SymDeferred:
		printf("Loaded symbols : Deferred\n"); // not actually loaded 
		break;

	default:
		printf("Loaded symbols: Unknown format.\n");
		break;
	}

	// Image name 

	if (strlen(ModuleInfo.ImageName) > 0)
	{
		printf("Image name: %s \n", ModuleInfo.ImageName);
	}

	// Loaded image name 

	if (strlen(ModuleInfo.LoadedImageName) > 0)
	{
		printf("Loaded image name: %s \n", ModuleInfo.LoadedImageName);
	}

	// Loaded PDB name 

	if (strlen(ModuleInfo.LoadedPdbName) > 0)
	{
		printf("PDB file name: %s \n", ModuleInfo.LoadedPdbName);
	}

	// Is debug information unmatched ? 
	// (It can only happen if the debug information is contained 
	// in a separate file (.DBG or .PDB) 

	if (ModuleInfo.PdbUnmatched || ModuleInfo.DbgUnmatched)
	{
		printf("Warning: Unmatched symbols. \n");
	}

	// Contents 

		// Line numbers available ? 

	printf("Line numbers: %s \n", ModuleInfo.LineNumbers ? "Available" : "Not available");

	// Global symbols available ? 

	printf("Global symbols: %s \n", ModuleInfo.GlobalSymbols ? "Available" : "Not available");

	// Type information available ? 

	printf("Type information: %s \n", ModuleInfo.TypeInfo ? "Available" : "Not available");

	// Source indexing available ? 

	printf("Source indexing: %s \n", ModuleInfo.SourceIndexed ? "Yes" : "No");

	// Public symbols available ? 

	printf("Public symbols: %s \n", ModuleInfo.Publics ? "Available" : "Not available");


}
#endif