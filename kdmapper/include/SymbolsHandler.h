/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

#pragma once
#include <stdio.h>
#include <intrin.h>
#include <Windows.h>

#include "DataStructs.h"

#define FUNCOFFSET_PATH	(PCSTR)".\\FunctionsOffset.txt"

#ifdef DEBUG
#define SYM_FROM_PDB_EXE (PCSTR)"SymbolsFromPDB_Debug.exe"
#else
#define SYM_FROM_PDB_EXE (PCSTR)"SymbolsFromPDB.exe"
#endif

//for use in kdmapper
extern SYM_INFO_ARRAY SymbolsInfoArray;

DWORD Crc32Str(
	IN PCSTR Str
);

BOOL GetSymbolsInfoFromFile(
	OUT PSYM_INFO_ARRAY pMiniSymInfoArray
);

BOOL ClearSymInfoArray(
	IN OUT PSYM_INFO_ARRAY pSymInfoArray
);

DWORD GetSymbolOffsetByHash(
	IN PSYM_INFO_ARRAY pSymInfoArray, 
	IN DWORD SymHash
);

DWORD GetSymbolOffsetByName(
	IN PSYM_INFO_ARRAY pSymInfoArray, 
	IN PCSTR SymName
);