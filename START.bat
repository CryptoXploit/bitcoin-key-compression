@Echo Off
COLOR 0F

SET file=addr.txt

setlocal enabledelayedexpansion

SET sessFile=_session.txt

SET Address=0
echo [~] calc total Address in file "!file!" ..
For /F %%a In (%file%) Do (
	SET /a Address+=1
)

SET lastN=0
IF EXIST !sessFile! (
	SET /P lastN=<!sessFile!
)

SET n=0
For /F %%a In (%file%) Do (
	echo =================================================
	REM date /T && time /T
	powershell Get-Date
	echo [!n!/!Address!] %%a

	IF !lastN! == !n! (
		echo !n!>!sessFile!

		R-Scaner.py  %%a
		REM timeout /T 1

		SET /a lastN+=1
	)

	SET /a n+=1
)

pause
