@echo off
adb kill-server
adb start-server
adb connect emulator-5554
cls
adb -s emulator-5554 shell mkdir /data/data/com.pubg.krmobile/obnox
cls
adb -s emulator-5554 shell content insert --uri content://settings/secure --bind name:s:android_id --bind value:s:%random%6b1a77f674510efbe5216b1b1b41%random%
cls
adb -s emulator-5554 shell chmod -R 777 /data/data/com.pubg.krmobile/obnox
cls
adb -s emulator-5554 shell cp /data/data/com.pubg.krmobile/shared_prefs/device_id.xml /data/data/com.pubg.krmobile/obnox
cls
adb -s emulator-5554 pull /data/data/com.pubg.krmobile/shared_prefs/device_id.xml %TEMP%
cls
findstr /v /i /c:"uuid" /c:"oranges" %TEMP%\device_id.xml >%TEMP%\device_id2.xml
cls
set tool= 32
Setlocal EnableDelayedExpansion
Set RNDtool=%tool%
Set Alphanumer=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
Set obnox=%Alphanumer%987654321
:NIILoop
IF NOT "%obnox:~18%"=="" SET obnox=%obnox:~9%& SET /A NII+=9& GOTO :NIILoop
SET UC=%obnox:~9,1%
SET /A NII=NII+UC
Set Count=0
SET RndAlphaNum=
:loop
Set /a Count+=1
SET RND=%Random%
Set /A RND=RND%%%NII%
SET RndAlphaNum=!RndAlphaNum!!Alphanumer:~%RND%,1!
If !Count! lss %RNDtool% goto loop
set inputfile=%TEMP%\device_id2.xml
set outputfile=%TEMP%\device_id3.xml
DEL %outputfile%
set "n1=    ^<string name="uuid"^>"
set "n2=^</string^>"
set nn=%n1:"=%%RndAlphaNum:"=%%n2:"=%
echo %n1%%RndAlphaNum%%n2%

    for /f "usebackq delims="  %%a in ("%inputfile%") do (
          if "%%~a"=="</map>" >>"%outputfile%" echo !nn!
          >>"%outputfile%" echo(%%a
    )
	
cls
powershell -Command "(gc %TEMP%\device_id3.xml) -replace 'uuid', '"""uuid"""' | Out-File -encoding ASCII %TEMP%\device_id3.xml"
cls
adb -s emulator-5554 push %TEMP%\device_id3.xml /data/data/com.pubg.krmobile/shared_prefs/
cls
adb -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile/databases/*
adb -s emulator-5554 shell rm -rf /data/data/com.pubg.krmobile/code_cache/*
cls
adb -s emulator-5554 shell mv /data/data/com.pubg.krmobile/shared_prefs/device_id3.xml /data/data/com.pubg.krmobile/shared_prefs/device_id.xml
cls
exit

