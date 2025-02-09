//TheCruZ Remake

#ifdef PDB_OFFSETS

#include <string>
#include <vector>

#define SYM_FROM_PDB_EXE L"SymbolsFromPDB.exe"

struct symOffset {
	unsigned long long offset{};
	std::wstring name{};
};

class KDSymbolsHandler
{

public:
	KDSymbolsHandler() {
	};

	static KDSymbolsHandler* GetInstance()
	{
		static KDSymbolsHandler instance{};
		return &instance;
	}

	bool ReloadFile(std::wstring path, std::wstring updater);
	unsigned long long GetOffset(std::wstring name);

private:
	std::vector<symOffset> symbols{};
};

#endif