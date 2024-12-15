/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

//for use in KDMapper

#pragma once
#include <stdio.h>
#include <intrin.h>
#include <Windows.h>//probably already included somewhere

#include "DataStructs.hpp"

///////////////////////////////////
//This macro is used to enable the use of the SymbolsHandler functions,if for any reasons you don't want to use PDB Offsets, you can still use the original method of sig scanning the kernel to get the target addresses
///*#####################*/

#define PDB_OFFSETS

///*#####################*/
///////////////////////////////////


#ifdef PDB_OFFSETS

///////////////////////
//macro defines
#define FUNCOFFSET_PATH	(PCSTR)".\\SymbolsOffset.txt"

#ifdef DEBUG
#define SYM_FROM_PDB_EXE (PCSTR)"SymbolsFromPDB_Debug.exe"
#else
#define SYM_FROM_PDB_EXE (PCSTR)"SymbolsFromPDB.exe"
#endif
///////////////////////

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


//just need this class to init the Symbols Info Array and clear it after main is done (usage of RAII).
class CSymInfo
{
	PSYM_INFO_ARRAY m_pSymInfoArray = NULL;

public:
	bool m_IsValid = false;

public:
	CSymInfo(PSYM_INFO_ARRAY pSymInfoArray)
	{
		m_IsValid = GetSymbolsInfoFromFile(pSymInfoArray);
		if (m_IsValid)
		{
			m_pSymInfoArray = pSymInfoArray;
		}
	}

	~CSymInfo()
	{
		ClearSymInfoArray(m_pSymInfoArray);
	}
};

#endif