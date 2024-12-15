#include "SymbolsHandler.hpp"

//for use in KDMapper

#ifdef PDB_OFFSETS

SYM_INFO_ARRAY SymbolsInfoArray = { NULL };

DWORD Crc32Str(IN PCSTR Str)
{
	if (!Str)
		return 0;

	DWORD Crc32 = 0;
	size_t Index = 0;
	while (*(Str + Index))
	{
		Crc32 = _mm_crc32_u8(Crc32, *(Str + Index));
		++Index;
	}

	return Crc32;
}

BOOL GetSymbolsInfoFromFile(OUT PSYM_INFO_ARRAY pSymInfoArray)
{
	if (system(SYM_FROM_PDB_EXE) != 0)
	{
		printf("[-] Failed To Generate Symbols Offset File.\n");
		return FALSE;
	}

	if (!pSymInfoArray)
	{
		printf("[-] Error: MiniSymInfoArray Ptr is NULL.\n");
		return FALSE;
	}
	pSymInfoArray->SymbolsArray = NULL;
	pSymInfoArray->ElementsCount = 0;

	HANDLE hFile = CreateFileA(FUNCOFFSET_PATH, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf(("[-] Failed To Open hFile: %s.\n-> Error: %u \n"), FUNCOFFSET_PATH, GetLastError());
		return FALSE;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);
	if (!FileSize)
	{
		printf("[-] Error: Offset hFile Is Empty.\n");
		CloseHandle(hFile);
		return 0;
	}

	PBYTE Buffer = (PBYTE)malloc(FileSize);
	if (!Buffer)
	{
		printf("[-] Error: Failed To Allocate Memory For hFile Buffer.\n");
		CloseHandle(hFile);
		return 0;
	}

	BOOL IsRead = ReadFile(hFile, Buffer, FileSize, NULL, NULL);
	CloseHandle(hFile);
	if (!IsRead)
	{
		printf("[-] Error: Failed To Read Data From File.\n");
		free(Buffer);
		return 0;
	}

	DWORD Index = 0;
	SIZE_T LinesCount = 0;
	do {
		if (Buffer[Index] == '\n')
		{
			++LinesCount;
		}
		++Index;
	} while (Index <= FileSize);

	if (!LinesCount)
	{
		printf("[-] Error: Failed To Read Data From hFile.\n");
		free(Buffer);
		return 0;
	}

	Index = 0;
	PSYM_INFO MiniSymInfoArray = (PSYM_INFO)malloc(sizeof(SYM_INFO) * LinesCount);
	if (!MiniSymInfoArray)
	{
		printf("[-] Error: Failed To Allocate Memory For Symbols Info Array.\n");
		free(Buffer);
		return 0;
	}
	memset(MiniSymInfoArray, 0, sizeof(SYM_INFO) * LinesCount);

	BOOL IsComma = FALSE;//for simple check that the file has at least a valid line 
	SIZE_T Count = 0;
	SIZE_T Line = 0;
	char* SymName = NULL;
	do {
		if (Buffer[Index] == ',')
		{
			IsComma = TRUE;
			SymName = (PCHAR)malloc(Count + 1);
			if (!SymName)
			{
				printf("[-] Error: Failed To Allocate Memory For Symbol Name.\n");
				break;
			}
			memcpy(SymName, &Buffer[Index - Count], Count);
			SymName[Count] = '\0';
			MiniSymInfoArray[Line].SymbolName = SymName;
			MiniSymInfoArray[Line].Crc32Hash = Crc32Str(SymName);
			SymName = NULL;
			Count = 0;
		}
		else if (Buffer[Index] == '\n')
		{
			Buffer[Index] = '\0';
			DWORD Offset = NULL;
			sscanf_s((PCSTR)(Buffer + Index - Count), "0x%X", &Offset);
			MiniSymInfoArray[Line].SymbolOffset = Offset;

			++Line;
			Count = 0;
		}
		else
		{
			++Count;
		}

		++Index;
	} while (Index < FileSize);

	free(Buffer);

	if ((Index != FileSize) || !Line || !IsComma)
	{
		for (SIZE_T i = 0; i < Line; ++i)
		{
			if (MiniSymInfoArray[i].SymbolName)
			{
				free((PVOID)MiniSymInfoArray[i].SymbolName);
				MiniSymInfoArray[i].SymbolName = NULL;
			}
		}
		return 0;
	}

	pSymInfoArray->SymbolsArray = MiniSymInfoArray;
	pSymInfoArray->ElementsCount = Line;
	return 1;
}

BOOL ClearSymInfoArray(IN OUT PSYM_INFO_ARRAY pSymInfoArray)
{
	if (!pSymInfoArray || !pSymInfoArray->ElementsCount)
	{
		printf("[-] Error: Invalid Parameter.\n");
		return FALSE;
	}

	PSYM_INFO SymInfoArray = pSymInfoArray->SymbolsArray;
	if (!SymInfoArray)
	{
		printf("[-] Error: The Array Is Already Empty.\n");
		return FALSE;
	}

	for (SIZE_T i = 0; i < pSymInfoArray->ElementsCount; ++i)
	{
		if (SymInfoArray[i].SymbolName)
		{
			free((PVOID)SymInfoArray[i].SymbolName);
			SymInfoArray[i].SymbolName = NULL;
		}
	}
	free(SymInfoArray);
	pSymInfoArray->SymbolsArray = NULL;
	pSymInfoArray->ElementsCount = 0;

	return TRUE;
}

DWORD GetSymbolOffsetByHash(IN PSYM_INFO_ARRAY pSymInfoArray, IN DWORD SymHash)
{
	if (!pSymInfoArray || !SymHash)
	{
		printf("[-] Error: Invalid Parameter.\n");
		return 0;
	}
	PSYM_INFO SymInfoArray = pSymInfoArray->SymbolsArray;
	if (!SymInfoArray)
	{
		printf("[-] Error: Failed To Sym Offset, The Sym Info Array Is Empty.\n");
		return FALSE;
	}

	for (SIZE_T i = 0; i < pSymInfoArray->ElementsCount; ++i)
	{
		if (SymInfoArray[i].Crc32Hash == SymHash)
		{
			return SymInfoArray[i].SymbolOffset;
		}
	}

	return 0;
}

DWORD GetSymbolOffsetByName(IN PSYM_INFO_ARRAY pSymInfoArray, IN PCSTR SymName)
{
	DWORD Hash = Crc32Str(SymName);
	return GetSymbolOffsetByHash(pSymInfoArray, Hash);
}

#endif