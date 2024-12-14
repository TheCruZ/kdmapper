
#include "SymbolsHandler.h"

int main()
{
	if (system("\"\"%cd%\"\\Tools\\SymCheck.bat\"") != 0)
	{
		printf("SymCheck.bat Hash Failed.\n");
		system("pause");
		return -1;
	}

	if(!GenerateOffsetFile())
	{
		system("pause");
		return -1;
	}
	printf("\n>> Successfully Generated Offsets File. <<\n");
	return 0;
}