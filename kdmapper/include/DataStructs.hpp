/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

//for use in KDMapper

#pragma once

#define Elements_Count(Array,Type) (sizeof(Array) / sizeof(Type))


typedef struct _SYM_INFO
{
	PCSTR SymbolName;
	DWORD SymbolOffset;
	DWORD Crc32Hash;
}SYM_INFO, * PSYM_INFO;

typedef struct SYM_INFO_ARRAY
{
	PSYM_INFO SymbolsArray;
	SIZE_T ElementsCount;
}SYM_INFO_ARRAY, * PSYM_INFO_ARRAY;
