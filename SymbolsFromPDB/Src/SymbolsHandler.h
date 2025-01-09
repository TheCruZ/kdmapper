/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

#pragma once
///////////////////////////////////////////////////////////////////////////////
//
// some of the following functions are imported made by: 
// 
// Author: Oleg Starodumov
// https://www.debuginfo.com/examples/dbghelpexamples.html
//

#include "DataStructs.h"
#include <dbghelp.h>
#pragma comment( lib, "dbghelp.lib" )


#ifdef UNICODE
#define NTOSKRNL_PATH		L".\\Tools\\Symbols\\ntkrnlmp.pdb"
#define WDFILTER_PATH		L".\\Tools\\Symbols\\WdFilter.pdb"
#define CIDLL_PATH			L".\\Tools\\Symbols\\ci.pdb"

#define SYM_OFFSETS_PATH		L"SymbolsOffset.txt"

#define PATH_TYPE			PCWSTR
#else
#define NTOSKRNL_PATH		".\\Tools\\Symbols\\ntkrnlmp.pdb"
#define WDFILTER_PATH		".\\Tools\\Symbols\\WdFilter.pdb"
#define CIDLL_PATH			".\\Tools\\Symbols\\ci.pdb"

#define FUNCOFFSET_PATH		"SymbolsOffset.txt"

#define PATH_TYPE			PCSTR
#endif




BOOLEAN GenerateOffsetFile(
	void
);

BOOLEAN InitKernelSymbolsList(
	IN PATH_TYPE FilePath,
	IN OUT PSYM_INFO_ARRAY pSymbolsArray
);

BOOLEAN GetFileParams(IN 
	PATH_TYPE pFileName,
	OUT uintptr_t* BaseAddr,
	OUT DWORD* FileSize
);

BOOLEAN _GetFileSize(
	IN PATH_TYPE pFileName,
	OUT DWORD* FileSize
);

#ifndef NDEBUG
void ShowSymbolInfo(
	IN uintptr_t ModBase
);
#endif