/*
#####################
# MoHieDDiNNe Codes #
#####################
*/

//for use in KDMapper

#pragma once
#include <iostream>
#include <vector>
#include <stdio.h>
#include <intrin.h>
#include <Windows.h>//probably already included somewhere


#include "DataStructs.hpp"

///////////////////////////////////
//This macro is used to enable the use of the SymbolsHandler functions,if for any reasons you don't want to use PDB Offsets, you can still use the original method of sig scanning the kernel to get the target addresses
///*#####################*/

//#define PDB_OFFSETS

///*#####################*/
///////////////////////////////////


#ifdef PDB_OFFSETS

///////////////////////
//macro defines
#define MAX_SYM_NAME_LENGTH (DWORD)50 //could be increased if some symbols name are over 50 characters   

#ifdef DEBUG
#ifdef UNICODE
#define SYM_OFFSETS_PATH	(PCWSTR)L"..\\Bin\\SymbolsOffset.txt"
#else
#define SYM_OFFSETS_PATH	(PCSTR)"..\\Bin\\SymbolsOffset.txt"
#endif
#else
#ifdef UNICODE
#define SYM_OFFSETS_PATH	(PCWSTR)L".\\SymbolsOffset.txt"
#else
#define SYM_OFFSETS_PATH	(PCSTR)".\\SymbolsOffset.txt"
#endif
#endif

#ifdef DEBUG
#define SYM_FROM_PDB_EXE (PCSTR)"cd ..\\Bin\\ && SymbolsFromPDB_Debug.exe"
#else
#define SYM_FROM_PDB_EXE (PCSTR)"SymbolsFromPDB.exe"
#endif
///////////////////////

extern std::vector<SYM_INFO>  SymbolsInfoArray;
extern PTCHAR SymbolsOffsetFilePath;

inline DWORD Crc32Str(
	IN PCSTR Str
);

BOOL GetSymbolsInfoFromFile(
	OUT std::vector<SYM_INFO>* pSymInfoArray,
	IN OPTIONAL bool UpdateOffsetsFile = true
);

DWORD GetSymbolOffsetByHash(
	IN const std::vector<SYM_INFO>& pSymInfoArray,
	IN DWORD SymHash
);

DWORD GetSymbolOffsetByName(
	IN const std::vector<SYM_INFO>& pSymInfoArray,
	IN const std::string& SymName
);

//just need this class to init the Symbols Info Array and clear it after main is done (usage of RAII).
class CSymInfo
{
	std::vector<SYM_INFO>* m_pSymInfoArray{};
public:
	bool m_IsValid = false;

public:
	CSymInfo(std::vector<SYM_INFO> *pSymInfoArray)
	{
		m_IsValid = GetSymbolsInfoFromFile(pSymInfoArray);
		if(m_IsValid)
		{
			m_pSymInfoArray = pSymInfoArray;
		}
	}

	CSymInfo(std::vector<SYM_INFO>* pSymInfoArray ,const bool UpdateOffsetsFile)
	{
		m_IsValid = GetSymbolsInfoFromFile(pSymInfoArray, UpdateOffsetsFile);
		if (m_IsValid)
		{
			m_pSymInfoArray = pSymInfoArray;
		}
	}

	~CSymInfo()
	{
		if (m_pSymInfoArray)
			m_pSymInfoArray->clear();
	}
};

#endif