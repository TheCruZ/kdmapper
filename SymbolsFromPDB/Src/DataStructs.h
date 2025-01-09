/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

#pragma once

#include "Defines.h"

#define Elements_Count(Array,Type) (sizeof(Array) / sizeof(Type))

typedef struct _SYM_INFO
{
	PVOID SymbolAddress;
	PCSTR SymbolName;
	DWORD NameLen;
	DWORD SymbolOffset;
}SYM_INFO, * PSYM_INFO;

typedef struct _SYM_INFO_ARRAY
{
	PSYM_INFO SymbolsArray;
	SIZE_T ElementsCount;
}SYM_INFO_ARRAY, * PSYM_INFO_ARRAY;

typedef struct _SYMBOLS_DATA
{
	PCSTR PDBFileName;
	SYM_INFO_ARRAY SymbolsInfoArray;
}SYMBOLS_DATA, *PSYMBOLS_DATA;
