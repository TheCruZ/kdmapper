#include "SymbolsHandler.hpp"

//for use in KDMapper

#ifdef PDB_OFFSETS

std::vector<SYM_INFO> SymbolsInfoArray{};
PTCHAR SymbolsOffsetFilePath = NULL;

inline DWORD Crc32Str(IN PCSTR Str)
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

BOOL GetSymbolsInfoFromFile(OUT std::vector<SYM_INFO> *pSymInfoArray, IN OPTIONAL bool UpdateOffsetsFile)
{
	if (!pSymInfoArray)
	{
		printf("[-] Error: SymInfoArray Ptr is NULL.\n");
		return FALSE;
	}
	pSymInfoArray->clear();

	HANDLE hFile;
	bool Failed = false;
	do {
		if (SymbolsOffsetFilePath)
		{
			hFile = CreateFile(SymbolsOffsetFilePath, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, 0, NULL);
			break;
		}

	RetryGeneratingFile:
		if (Failed || UpdateOffsetsFile)
		{
			printf("[+] Generating Default Offsets File\n");
			if (system(SYM_FROM_PDB_EXE) != 0)
			{
				printf("[-] Failed To Generate Symbols Offset File.\n");
				return FALSE;
			}
		}
	TryDefault:
		hFile = CreateFile(SYM_OFFSETS_PATH, GENERIC_READ, FILE_SHARE_READ,
			NULL, OPEN_EXISTING, 0, NULL);
	} while (0);

	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		if (!Failed)
		{
			if (SymbolsOffsetFilePath)
			{
				printf("[>] Warning: The Supplied File Path Is Invalid --> Switching To Default Offsets File.\n");
				SymbolsOffsetFilePath = NULL;//Reset The Global Path Variable
				goto TryDefault;
			}
			
			printf("[>] Warning: Failed To Access Default Offsets File --> Default File Is Not Valid.\n");
			Failed = true;	
			goto RetryGeneratingFile;
		}
#ifdef UNICODE
		printf(("[-] Failed To Open Offsets File: %ls.\n-> Error: %u \n"), SYM_OFFSETS_PATH, GetLastError());
#else
		printf(("[-] Failed To Open Offsets File: %s.\n-> Error: %u \n"), FUNCOFFSET_PATH, GetLastError());
#endif
		return FALSE;
	}

	DWORD FileSize = GetFileSize(hFile, NULL);
	if (!FileSize)
	{
		printf("[-] Error: Offset File Is Empty.\n");
		CloseHandle(hFile);
		return FALSE;
	}

	std::unique_ptr<char> BufferLocalPtr(new char[FileSize]);
	PCHAR Buffer = BufferLocalPtr.get();
	if (!Buffer)
	{
		printf("[-] Error: Failed To Allocate Memory For Offsets File Buffer.\n");
		CloseHandle(hFile);
		return FALSE;
	}

	BOOL IsRead = ReadFile(hFile, Buffer, FileSize, NULL, NULL);
	CloseHandle(hFile);
	if (!IsRead)
	{
		printf("[-] Error: Failed To Read Data From Offsets File.\n");
		return FALSE;
	}

	SIZE_T Index = 0;
	SIZE_T LinesCount = 0;
	do {
		if (Buffer[Index] == '\n')
		{
			++LinesCount;
		}
		++Index;
	} while (Index < FileSize);

	if (!LinesCount)
	{
		printf("[-] Error: Failed To Get Lines Count In Offsets File.\n");
		return FALSE;
	}

	pSymInfoArray->reserve(LinesCount);
	Index = 0;

	SIZE_T Count = 0;
	SIZE_T Line = 0;
	SIZE_T CommaCount = 0; 
	SYM_INFO SymInfo;
	do {
		if (Buffer[Index] == ',')
		{
			std::string SymName(&Buffer[Index - Count], &Buffer[Index]);
			SymInfo.Crc32Hash = Crc32Str(SymName.c_str());
			Count = 0;
			++CommaCount;
		}
		else if (Buffer[Index] == '\n')
		{
			Buffer[Index] = '\0';
			DWORD Offset = NULL;
			sscanf_s((PCSTR)(Buffer + Index - Count), "0x%X", &Offset);
			SymInfo.SymbolOffset = Offset;
			pSymInfoArray->emplace_back(SymInfo);

			SymInfo.Crc32Hash = 0;
			SymInfo.Crc32Hash = 0;
			++Line;
			Count = 0;
		}
		else
		{
			if (Count > MAX_SYM_NAME_LENGTH)
			{
				printf("Error: Max Symbol Length Exceeded.\n");
				return FALSE;
			}
			++Count;
		}

		++Index;
	} while (Index < FileSize);

	if (!Line || (Line != CommaCount) || (Index != FileSize))
	{
		return FALSE;
	}
	return TRUE;
}

DWORD GetSymbolOffsetByHash(IN const std::vector<SYM_INFO>& SymInfoArray, IN DWORD SymHash)
{
	if (SymInfoArray.empty() || !SymHash)
	{
		printf("[-] Error: Invalid Parameter.\n");
		return 0;
	}

	for (SYM_INFO SymInfo:SymInfoArray)
	{
		if (SymInfo.Crc32Hash == SymHash)
		{
			return SymInfo.SymbolOffset;
		}
	}

	return 0;
}

DWORD GetSymbolOffsetByName(IN const std::vector<SYM_INFO>& SymInfoArray, IN const std::string& SymName)
{
	DWORD Hash = Crc32Str(SymName.c_str());
	return GetSymbolOffsetByHash(SymInfoArray, Hash);
}

#endif