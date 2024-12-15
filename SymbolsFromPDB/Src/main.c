
#include "SymbolsHandler.h"

int main()
{
	if (system("\"\"%cd%\"\\Tools\\SymCheck.bat\"") != 0)
	{
		printf("\nSymCheck.bat Hash Failed.\n\n");
		system("pause");
		return -1;
	}

	if(!GenerateOffsetFile())
	{
		system("pause");
		return -1;
	}
	printf("\n>> Successfully Generated Offsets File. <<\n\n");
	return 0;
}