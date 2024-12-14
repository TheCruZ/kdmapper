#pragma once
#include "SymbolsHandler.h"

//just need this class to init the Symbols Info Array and clear it after main is done.

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
			m_pSymInfoArray = pSymInfoArray ;
		}
	}

	~CSymInfo()
	{
		ClearSymInfoArray(m_pSymInfoArray);
	}
};