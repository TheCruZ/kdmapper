@ECHO OFF

SETLOCAL

set SymCheck="%cd%"\Tools\SymChk\symchk.exe
set SymbolsDir="%cd%"\Tools\Symbols\
set MS_Files=%SymbolsDir%MS_Files\

set "PDB_Files[0]=ntkrnlmp.pdb"
set "PDB_Files[1]=WdFilter.pdb" 
set "PDB_Files[2]=ci.pdb" 

set "FilesPath[0]=%systemroot%\System32\ntoskrnl.exe"
set "FilesPath[1]=%systemroot%\System32\drivers\wd\WdFilter.sys"
if not exist %FilesPath[1]% (
	set "FilesPath[1]=%systemroot%\System32\drivers\WdFilter.sys"
)
set "FilesPath[2]=%systemroot%\System32\ci.dll"

set /a "Index=0"
:for_loop
	call set Path=%%FilesPath[%Index%]%%
	echo #################################
	echo Getting Symbols For %Path%...
	%SymCheck% /r  %Path% /s SRV*%MS_Files%*http://msdl.microsoft.com/download/symbols
	echo #################################
	if %ERRORLEVEL% NEQ 0 ( 
	   exit %ERRORLEVEL% 
	)
	call set Target=%%PDB_Files[%Index%]%%
	dir /b /s %MS_Files%%Target%\ > fileslist.txt
	if %ERRORLEVEL% NEQ 0 ( 
	   exit %ERRORLEVEL% 
	)
	
	setlocal EnableDelayedExpansion
	set /a "Line=0"
	set "Paths[0]=crap"

	for /f "tokens=* delims=" %%i in (fileslist.txt) do (
		if !Line! GTR 1 (
			echo #################################
			echo Symbols Conflict Deleting %MS_Files%%Target% And Retrying
			echo #################################

			rmdir  /s /q %MS_Files%%Target%
			if %ERRORLEVEL% NEQ 0 ( 
				pause
				exit %ERRORLEVEL% 
			)
			if exist %SymbolsDir%%Target% (
				del %SymbolsDir%%Target%
				if %ERRORLEVEL% NEQ 0 ( 
					pause
					exit %ERRORLEVEL% 
				)
			)
			goto for_loop
		)
		
		set "Paths[!Line!]="%%i""
		set /a "Line+=1"
	)

	del fileslist.txt
	if %ERRORLEVEL% NEQ 0 ( 
	   exit %ERRORLEVEL% 
	)
	set SymPath=%Paths[1]%
	if not exist %SymPath% (
		echo #################################
		echo - Symbols File Does Not Exist: %SymPath%
		echo - Warning: If You Force The Software To Run Your PC Will Crash 
		echo #################################
		if exist %SymbolsDir%%Target% (del "%SymbolsDir%%Target%")
		pause
		exit -1
	)

	if not exist %SymbolsDir%%Target% (
		echo copying %SymPath% to "%SymbolsDir%
		%systemroot%\System32\xcopy /q/y %SymPath% %SymbolsDir%
		if not exist %SymbolsDir%%Target% (
			echo #################################
			echo - Failed To Copy PDB File: %Target%
			echo - Warning: If You Force The Software To Run Your PC Will Crash 
			echo #################################
			pause
			exit -1
		)
	)
	
	set /a "Index+=1"	
	if not defined PDB_Files[!Index!] goto exit_for_loop
goto for_loop
:exit_for_loop

echo #################################
echo Batch Script Done!
echo #################################

ENDLOCAL
::pause
exit %ERRORLEVEL%