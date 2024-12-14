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





//#define _CRT_SECURE_NO_WARNINGS
#define NTOSKRNL_PATH		".\\Tools\\Symbols\\ntkrnlmp.pdb"
#define WDFILTER_PATH		".\\Tools\\Symbols\\WdFilter.pdb"
#define CIDLL_PATH			".\\Tools\\Symbols\\ci.pdb"

#define FUNCOFFSET_PATH		"SymbolsOffset.txt"




BOOLEAN GenerateOffsetFile(
	void
);

BOOLEAN InitKernelSymbolsList(
	IN const CHAR* FilePath, 
	IN OUT PSYM_INFO_ARRAY pSymbolsArray
);

BOOLEAN GetFileParams(IN 
	const CHAR* pFileName, 
	OUT uintptr_t* BaseAddr,
	OUT DWORD* FileSize
);

BOOLEAN _GetFileSize(
	IN const CHAR* pFileName,
	OUT DWORD* FileSize
);

#ifndef NDEBUG
void ShowSymbolInfo(
	IN uintptr_t ModBase
);
#endif