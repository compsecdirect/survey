@ECHO OFF
rem ''''''''''''''''''''''''''''''''''''''''''''''''''
rem ' Orignal authors declined publication '
rem ' Updated to Windows 10 by jfersec(CompSec Direct) '
rem ' CompSec Direct asserts no claims of ownership/work products within this script '
rem ''''''''''''''''''''''''''''''''''''''''''''''''''
rem This script will conduct an initial survey of the target environment
rem tested on XP SP0 Pro, XP SP2 Pro, Win7, Vista, Windows 10, Windows Server 2019
color 0b
title Windows Survey

mode con lines=10000
mode con cols=160

set hour=%time: =0%
set VAR=%computername%-%date:~10,4%-%date:~4,2%-%date:~7,2%_%hour:~0,2%h_%time:~3,2%m

cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXOkOKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM TODO: Remove shameless branding ¯\_(?)_/¯
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNk:''''';dKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO;''''''''''oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM Follow us on Social Media
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMk,'''';dO00ko;:0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM L: company/compsec-direct  
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMWd'''',oNMMMMMMNo,kMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM T: @CompSecDirect / @jfersec
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMk'''',kMMMMMMMMMWk:KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM FB: /CompSecDirect/  
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMX;''''kMMMMMMMMMMMMKlNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMo''''dWMMMMMMMMMMMMMOoWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMO,'''lWMMMMMMMMMMMMMMMO0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMN:''',KMMMMMMMMMMMMMMMMMKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMk''''lMMMMMMMMMMMMMMMMMMWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMc''''0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMK,'''cWMMMMMMMMMMMMMWNXKKKXNWMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMk''''OMMMMMMMMMMMMWKkkkkkkkkkKWMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMo''';NMMMMMMMMMMMNkkkkkkkkkkkkONMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMW:'''oMMMMMMMMMWOX0kkkkkkkkkkkkkKMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMNOo,'''lKNMMMMNKx:'K0kkkkkkkkkkkkkKMMMMMMMMMMMMMMMMMMMMMMMM WINDOWS SURVEY FROM Declined Pub and jfersec @CompSecDirect
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMXo;'''''''',;::;,''''oNOkkkkkkkkkkkkk0XWMMMMMMMMMMMMMMMMMMMMM Version 1.1, Because why not
cmd.exe /c echo #MMMMMMMMMMMMMMMMMN:''''''''''''''',lk0KXWMKkkkkkkkkkkkkkkkKNMMMMMMMMMMMMMMMMMMM Date Jun 23, 2021
cmd.exe /c echo #MMMMMMMMMMMMMMMMMk'''''''''''''';kNMMMMMMMM0kkkkk0NWWX0kkkkkOXWMMMMMMMMMMMMMMMM 
cmd.exe /c echo #MMMMMMMMMMMMMMMMM0'''''''''''''cXMMMMMMMMMMNkkkkKMMMMMMNKkkkkkkKWMMMMMMMMMMMMMM MIT License, ShelfWare
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMd,''''''''''oNNMMMMMMMMMMNkkk0MMMMMMMMMWKOkkkkk0NMMMMMMMMMMMM No ownership rights expressed
cmd.exe /c echo #MMMMMMMMMMMWXWMMMMMKd;''''',lO0ooXMMMMMMMMM0kkxXMMMMMMMMMMMMNOkkkkk0NMMMMMMMMMM Make this script not suck: Hit up github
cmd.exe /c echo #MMMMMMMMMN0KWMMMMMMMMWXK00KXKxccccd0XWMMMMNKK0O0MMMMMMMMMMMMMMN0kkkkk0WMMMMMMMM Github: github.com/CompSecDirect/Survey
cmd.exe /c echo #MMMMMMMW0kNMMMMMMMMMMMMMMMMMMMN0xcccclodddoodk0XWMMMMMMMMMMMMMMMNOkkkkkKWMMMMMM 
cmd.exe /c echo #MMMMMMKdOWMMMMMMMMMMMMMMMMMMMMMMMKocccccccccccclOWMMMMMMMMMMMMMMMMXkkkkkONMMMMM Work Ratio: DP 89 / jfersec 11
cmd.exe /c echo #MMMMMOlKMMMMMMMMMMMMMMMMMMMMMMMMMMWdcccccccccccccOMMMMMMMMMMMMMMMMMNOkkkkkNMMMM
cmd.exe /c echo #MMMWxc0MMMMMMMMMMMMMMMMMMMMMMMMMMMM0cccccccccccccdMMMMMMMMMMMMMMMMMMW0kkkkkXMMM
cmd.exe /c echo #MMMxclNMMMMMMMMMMMMMMMMMMMMMMMMNKkdlccccccccccccckMMMMMMMMMMMMMMMMMMMNkkkkkOMMM
cmd.exe /c echo #MMKcccKMMMMMMMMMMMMMMMMMMWN0OxocccccccccccccccccdNMMMMMMMMMMMMMMMMMMMWkkkkkkWMM
cmd.exe /c echo #MMkccclkKNWWMMMWWNXK0OkxolccccccccoxOK0dlccccokKWMMMMMMMMMMMMMMMMMMMN0kkkkkKMMM
cmd.exe /c echo #MMOcccccccclllllcccccccccccccoxOKWMMMMMMWNNNWMMMMMMMWWWNNXXXXXXXXK0OkkkkOKNMMMM
cmd.exe /c echo #MMWklcccccccccccccccclodkO0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWWNNXXXXXXXNWWMMMMMMM 
cmd.exe /c echo #MMMMWX0kxxdddxxkOOKXNWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
cmd.exe /c echo #MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM


pause

color 0a

cmd.exe /c echo ###################################################################
cmd.exe /c echo #   WINDOWS SURVEY FROM Declined Pub and jfersec @CompSecDirect   #
cmd.exe /c echo #								  #
cmd.exe /c echo ###################################################################
cmd.exe /c echo. 


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #   YOUR WINDOWS SURVEY IS ABOUT TO BEGIN        #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

rem ' Untested in previous windows versions'
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            ADMIN/ELEVATED CHECK                #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

net session >nul 2>&1 > %VAR%-adminCheck.txt
 
If %ERRORLEVEL% == 0 (
    Echo "Running as admin user"
	Echo "Running as admin user" >> %VAR%-adminCheck.txt
) ELSE (
    Echo "WARNING: Not Running as admin user, some commands will not work"
	Echo "WARNING: Not Running as admin user, some commands will not work" >> %VAR%-adminCheck.txt
)

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      PROCESS LIST WITH MEMORY USAGE STATS      #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 


cmd.exe /c tasklist 
cmd.exe /c tasklist /v /fo csv >  %VAR%-tasklist.csv

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #         CURRENT WORKING DIRECTORY              #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c chdir
cmd.exe /c echo.

 

ver | find "2003" > nul
if %ERRORLEVEL% == 0 goto ver_pre-vista

ver | find "XP" > nul
if %ERRORLEVEL% == 0 goto ver_pre-vista

ver | find "2000" > nul
if %ERRORLEVEL% == 0 goto ver_pre-vista

ver | find "NT" > nul
if %ERRORLEVEL% == 0 goto ver_pre-vista

rem if not exist %SystemRoot%\system32\systeminfo.exe goto warnthenexit

rem systeminfo | find "OS Name" > %TEMP%\osname.txt
for /f "tokens=3*" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| Find "ProductName"') DO set vers=%%i %%j

cmd.exe /c echo ##################################################
cmd.exe /c echo #         OS VERSION			         #
cmd.exe /c echo ##################################################

echo %vers% As the detected OS
echo %vers% As the detected OS > %VAR%-hostinfo.txt

echo %vers% | find "Windows Vista" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows 7" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows 8" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows 10" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows Server 2008" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows Server 2012" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows Server 2016" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

echo %vers% | find "Windows Server 2019" > nul
if %ERRORLEVEL% == 0 goto ver_post-vista

rem goto warnthenexit

:ver_pre-vista
:Run Windows 2000 specific commands here.
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           CONFIRMING LAST BOOT TIME            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 
cmd.exe /c netsh diag show os /v | find "LastBootUpTime"
cmd.exe /c netsh diag show os /v | find "LastBootUpTime" >> %VAR%-hostinfo.txt
cmd.exe /c echo.

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                Checking User                   #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c echo. 
cmd.exe /c echo %USERDOMAIN%\%USERNAME%
cmd.exe /c echo %WINDIR%
cmd.exe /c echo %USERDOMAIN%\%USERNAME% >> %VAR%-hostinfo.txt
cmd.exe /c echo %WINDIR% >> %VAR%-hostinfo.txt

cmd.exe /c echo. 

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                  OS Check                      #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c "echo >OSVer.vbs Set OSSet = GetObject("winmgmts:{impersonationLevel=impersonate}!//./root/cimv2").ExecQuery("select caption, CSDVersion, SerialNumber from Win32_OperatingSystem")"

cmd.exe /c "echo >>OSVer.vbs For Each OS In OSSet"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Operating System=" ^& OS.Caption"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Service Pack=" ^& OS.CSDVersion"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Product ID=" ^& OS.SerialNumber"

cmd.exe /c "echo >>OSVer.vbs Next"

cmd.exe /c "cscript //nologo OSVer.vbs"

cmd.exe /c del OSVer.vbs

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            32 or 64-bit Check                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

Set RegQry=HKLM\Hardware\Description\System\CentralProcessor\0
 
REG.exe Query %RegQry% > checkOS.txt
 
Find /i "x86" < CheckOS.txt > StringCheck.txt
 
If %ERRORLEVEL% == 0 (
    Echo "This is a 32-bit Operating system"
) ELSE (
    Echo "This is a 64-bit Operating System"
)

cmd.exe /c del StringCheck.txt
cmd.exe /c del checkOS.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #         CURRENT WORKING DIRECTORY              #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c chdir
cmd.exe /c echo.

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              TARGET DATE\TIME                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c echo The TIME is: %time%
cmd.exe /c echo The DATE is: %date%
cmd.exe /c netsh diag show os /v | find "LocalDateTime"
cmd.exe /c echo.

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #               TARGET OS INFORMATION            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c netsh diag show os /v | find "Operating System"
cmd.exe /c netsh diag show os /v | find "CSName"
cmd.exe /c netsh diag show os /v | find "InstallDate"
cmd.exe /c netsh diag show os /v | find "SerialNumber"
cmd.exe /c netsh diag show os /v | find "RegisteredUser"
cmd.exe /c netsh diag show computer /v | find "PrimaryOwnerContact"
cmd.exe /c netsh diag show computer /v | find "PrimaryOwnerName"

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            TARGET PLATFORM INFORMATION         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c netsh diag show computer /v | find "Manufacturer"
cmd.exe /c netsh diag show computer /v | find "Model"
cmd.exe /c netsh diag show computer /v | find "Name"

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            TARGET USER INFORMATION             #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c netsh diag show computer /v | find "AdminPasswordStatus"
cmd.exe /c echo      1=Disabled, 2=Enabled, 3=Not Implemented, 4=Unknown
cmd.exe /c netsh diag show computer /v | find "UserName"
cmd.exe /c netsh diag show computer /v | find "Caption"

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            TARGET NETWORKING INFORMATION       #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c netsh diag show computer /v | find "Name"
cmd.exe /c netsh diag show computer /v | find "Domain"
cmd.exe /c netsh diag show computer /v | find "DomainRole"
cmd.exe /c echo VALUE MEANS 0=Standalone, 1=Member, 2=Standalone Server, 3=Member Server, 4=BDC, 5=PDC
cmd.exe /c netsh diag show computer /v | find "PartOfDomain"
cmd.exe /c netsh diag show computer /v | find "Roles"
cmd.exe /c netsh diag show computer /v | find "Workgroup"
cmd.exe /c netsh diag show os /v | find "NumberOfUsers"
cmd.exe /c netsh diag show os /v | find "NumberOfProcesses"

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      CHECKING COMPUTER'S PUBLIC IP ADDRESS     #
cmd.exe /c echo ##################################################
cmd.exe /c echo

rem ' Sourced from https://www.prajwaldesai.com/get-public-ip-address-using-powershell/'
powershell "Invoke-RestMethod -Uri ('https://ipinfo.io/') | tee %VAR%-networkinfo.txt"

cmd.exe /c echo var request = new ActiveXObject("Msxml2.XMLHTTP"); > ext_ip.js
cmd.exe /c echo var notyetready = 1; >> ext_ip.js

cmd.exe /c echo request.onreadystatechange=function() >> ext_ip.js 
cmd.exe /c echo { >> ext_ip.js
cmd.exe /c echo if(request.readyState==4) >> ext_ip.js
cmd.exe /c echo { >> ext_ip.js
cmd.exe /c echo WScript.Echo(request.responseText); >> ext_ip.js 
cmd.exe /c echo notyetready = 0; >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js
cmd.exe /c echo. >> ext_ip.js
cmd.exe /c echo request.open( "GET", "https://www.komar.org/cgi-bin/ip_to_country.pl", true ); >> ext_ip.js 
cmd.exe /c echo request.send(null); >> ext_ip.js 
cmd.exe /c echo. >> ext_ip.js
cmd.exe /c echo while( notyetready ) >> ext_ip.js 
cmd.exe /c echo { >> ext_ip.js 
cmd.exe /c echo WScript.Sleep( 100 ); >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js 

cmd.exe /c cscript ext_ip.js > result.html
cmd.exe /c find "Your IP Address" result.html
cmd.exe /c find "Your Hostname" result.html
cmd.exe /c find "Your Country Name" result.html

cmd.exe /c del ext_ip.js result.html

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW CHECKING NETWORK CONNECTION INFO      #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

 

cmd.exe /c netstat -an 
cmd.exe /c echo.

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #   NOW CHECKING NETWORK INTERFACE INFORMATION   #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c ipconfig /all
cmd.exe /c echo.
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW CHECKING NETWORK ROUTING INFO         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c route print
cmd.exe /c echo.
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            NOW CHECKING ARP INFO               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c arp -a 
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY NETWORK SHARES                #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net share
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY LOCAL USER ACCOUNTS           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net user
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY LOCAL GROUPS                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net localgroup
 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #   NOW DISPLAY USERS BELONGING TO ADMIN GROUP   #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net localgroup administrators
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY COMPUTERS IN MY WORKGROUP     #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net view
 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY DOMAIN INFO                   #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net view /domain
 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #             Checking Eventlogs                 #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c cscript %SYSTEMroot%\system32\eventquery.vbs /L security 

 

cmd.exe /c cscript %SYSTEMroot%\system32\eventquery.vbs /L system 

 

cmd.exe /c cscript %SYSTEMroot%\system32\eventquery.vbs /L application 

 

cmd.exe /c echo.
cmd.exe /c echo ######################################################
cmd.exe /c echo #    IF YOU WOULD LIKE A MORE VERBOSE OUTPUT RUN     #
cmd.exe /c echo #     "eventquery /L <logfile> /V" or run the        #
cmd.exe /c echo #           verbose_event_query script               #
cmd.exe /c echo ######################################################
cmd.exe /c echo. 

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                DRIVE INFORMATION               #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 


cmd.exe /c fsutil fsinfo drives
cmd.exe /c echo.

echo Free Disk Space on C:
cmd.exe /c fsutil volume diskfree c:
cmd.exe /c echo.

 
echo Free Disk Space on D:
cmd.exe /c fsutil volume diskfree d:
cmd.exe /c echo.

 
echo Free Disk Space on E:
cmd.exe /c fsutil volume diskfree e:
cmd.exe /c echo.

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           WHAT TYPE OF DRIVE IS C:?            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

 

cmd.exe /c vol c:
cmd.exe /c fsutil fsinfo drivetype c:
cmd.exe /c echo.

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           WHAT TYPE OF DRIVE IS D:?            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

 

cmd.exe /c vol d:
cmd.exe /c fsutil fsinfo drivetype d:
cmd.exe /c echo.

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           WHAT TYPE OF DRIVE IS E:?            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

 

cmd.exe /c vol e:
cmd.exe /c fsutil fsinfo drivetype e:
cmd.exe /c echo.

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo # If there are any more drives run fsutil again  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #     Further querying DRIVE INFORMATION         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c echo list disk > %systemroot%\driveinfo.txt
cmd.exe /c echo list volume > %systemroot%\driveinfo.txt

cmd.exe /c diskpart /s %systemroot%\driveinfo.txt

cmd.exe /c del %systemroot%\driveinfo.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #               SYSTEM INFORMATION               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

cmd.exe /c systeminfo

 

reg query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING SOFTWARE KEY               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



reg query "HKLM\Software" 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #       CHECKING CURRENTVERSION INFO KEY         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



reg query "HKLM\software\Microsoft\Windows NT\CurrentVersion"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #             CHECKING WINLOGON KEY              #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKLM\software\microsoft\windows NT\currentversion\winlogon"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #       VALUE IN LOCAL MACHINE RUN KEY           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN LOCAL MACHINE RUNONCE KEY        #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN LOCAL MACHINE WINDOWS KEY        #
cmd.exe /c echo #       LOOKING FOR APPINIT_DLL PRESENCE         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN CURRENT USER RUN KEY             #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN CURRENT USER RUNONCE KEY         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #       Checking TCPIP Network Configs           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces" /s

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #       Checking for Wireless Networks           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKLM\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #     IF USING WEP, KEY WILL BE STORED HERE      #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 
reg query "HKCU\SOFTWARE\Microsoft\WZCSVC\Parameters\Interfaces"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          Checking for LAN Computers            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComputerDescriptions"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING FOR COMPUTER NAME            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           CHECKING IE INFORMATION              #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKCU\Software\Microsoft\Internet Explorer"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING USER'S IE START PAGE         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

reg query "HKCU\Software\Microsoft\Internet Explorer\Main" | find "Start Page"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING USER'S IE TYPED URL's        #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

  

reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING PRINTER INFORMATION          #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



cmd.exe /c cscript %systemroot%\system32\prnjobs.vbs -l
cmd.exe /c cscript %systemroot%\system32\prncnfg.vbs -g

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING FW CONFIGRUATIONS            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c netsh firewall show config

 

cmd.exe /c netsh firewall show opmode

 

reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List"

 

reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\List"

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              PERFORMING CLEANUP                #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING SCHEDULED TASKS            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.
 
cmd.exe /c dir %SYSTEMROOT%\tasks

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING PREFETCH DIRECTORY         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.
 

cmd.exe /c dir %SYSTEMROOT%\prefetch



cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING "AT" JOBS                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c at

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            SCRIPT COMPLETE                     #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

 

goto exit

:ver_post-vista
:Run Windows NT specific commands here.
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #        PROCESS LIST WITH CPU TIME STATS        #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

 

powershell get-process > %VAR%-get-process.txt 
cmd.exe /c type *-get-process.txt

 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #         PROCESS LIST WITH FULL PATH            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

powershell get-process ^| format-table name,path > %VAR%-get-process-full.txt
cmd.exe /c type *-get-process-full.txt


 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              LISTING DRIVERS		         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

powershell "driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name','state','path' | format-table -wrap -auto"
cmd.exe /c driverquery /fo csv /v >> %VAR%-drivers.csv
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           CONFIRMING LAST BOOT TIME            # 
cmd.exe /c echo ##################################################
cmd.exe /c echo. 
cmd.exe /c systeminfo > sysinfo.txt
cmd.exe /c findstr /c:"Boot Time" sysinfo.txt
cmd.exe /c findstr /c:"Boot Time" sysinfo.txt >> %VAR%-hostinfo.txt

cmd.exe /c echo.

 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                CHECKING USER                   #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 
cmd.exe /c echo %USERDOMAIN%\%USERNAME%
cmd.exe /c echo %USERDOMAIN%\%USERNAME% >> %VAR%-hostinfo.txt
cmd.exe /c echo %WINDIR%
cmd.exe /c echo %WINDIR% >> %VAR%-hostinfo.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                  OS CHECK                      #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c "echo >OSVer.vbs Set OSSet = GetObject("winmgmts:{impersonationLevel=impersonate}!//./root/cimv2").ExecQuery("select caption, CSDVersion, SerialNumber from Win32_OperatingSystem")"

cmd.exe /c "echo >>OSVer.vbs For Each OS In OSSet"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Operating System=" ^& OS.Caption"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Service Pack=" ^& OS.CSDVersion"

cmd.exe /c "echo >>OSVer.vbs wscript.echo "Product ID=" ^& OS.SerialNumber"

cmd.exe /c "echo >>OSVer.vbs Next"

cmd.exe /c "cscript //nologo OSVer.vbs"
cmd.exe /c "cscript //nologo OSVer.vbs" >> %VAR%-hostinfo.txt

cmd.exe /c del OSVer.vbs

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            32 OR 64-BIT CHECK                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

Set RegQry=HKLM\Hardware\Description\System\CentralProcessor\0
 
REG.exe Query %RegQry% > checkOS.txt
 
Find /i "x86" < CheckOS.txt > StringCheck.txt
 
If %ERRORLEVEL% == 0 (
    Echo "This is a 32-bit Operating system"
	Echo "This is a 32-bit Operating system" >> %VAR%-hostinfo.txt
) ELSE (
    Echo "This is a 64-bit Operating System"
	Echo "This is a 64-bit Operating System" >> %VAR%-hostinfo.txt
)

cmd.exe /c del StringCheck.txt
cmd.exe /c del checkOS.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              RETRIEVING OS CULTURE             #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

powershell get-culture
powershell get-culture >> %VAR%-hostinfo.txt


 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              TARGET DATE\TIME                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c echo The DATE is: %date%
cmd.exe /c echo The DATE is: %date% >> %VAR%-hostinfo.txt
cmd.exe /c echo The TIME is: %time% 
cmd.exe /c echo The TIME is: %time% >> %VAR%-hostinfo.txt
powershell get-date
powershell get-date >> %VAR%-hostinfo.txt
cmd.exe /c echo.

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #               TARGET OS INFORMATION            #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c findstr /i /c:"Host Name" sysinfo.txt
cmd.exe /c findstr /i /c:"Host Name" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"OS Name" sysinfo.txt
cmd.exe /c findstr /i /c:"OS Name" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"OS Version" sysinfo.txt
cmd.exe /c findstr /i /c:"OS Version" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"OS Configuration" sysinfo.txt
cmd.exe /c findstr /i /c:"OS Configuration" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Logon Server" sysinfo.txt
cmd.exe /c findstr /i /c:"Logon Server" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Original Install Date" sysinfo.txt
cmd.exe /c findstr /i /c:"Original Install Date" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Product ID" sysinfo.txt
cmd.exe /c findstr /i /c:"Product ID" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Registered Owner" sysinfo.txt
cmd.exe /c findstr /i /c:"Registered Owner" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Registered Organization" sysinfo.txt
cmd.exe /c findstr /i /c:"Registered Organization" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Domain" sysinfo.txt
cmd.exe /c findstr /i /c:"Domain" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Network Card" sysinfo.txt
cmd.exe /c findstr /i /c:"Network Card" sysinfo.txt >> %VAR%-hostinfo.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            TARGET PLATFORM INFORMATION         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c findstr /i /c:"System Manufacturer" sysinfo.txt
cmd.exe /c findstr /i /c:"System Model" sysinfo.txt
cmd.exe /c findstr /i /c:"System Type" sysinfo.txt
cmd.exe /c findstr /i /c:"Processor(s)" sysinfo.txt

cmd.exe /c findstr /i /c:"System Manufacturer" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"System Model" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"System Type" sysinfo.txt >> %VAR%-hostinfo.txt
cmd.exe /c findstr /i /c:"Processor(s)" sysinfo.txt >> %VAR%-hostinfo.txt


 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #   NOW CHECKING NETWORK INTERFACE INFORMATION   #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c ipconfig /all 
cmd.exe /c ipconfig /all >> %VAR%-hostinfo.txt
cmd.exe /c echo.


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      CHECKING COMPUTER'S PUBLIC IP ADDRESS     #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

rem ' Sourced from https://www.prajwaldesai.com/get-public-ip-address-using-powershell/'
powershell "Invoke-RestMethod -Uri ('https://ipinfo.io/') | tee %VAR%-networkinfo.txt"

cmd.exe /c echo var request = new ActiveXObject("Msxml2.XMLHTTP"); > ext_ip.js
cmd.exe /c echo var notyetready = 1; >> ext_ip.js

cmd.exe /c echo request.onreadystatechange=function() >> ext_ip.js 
cmd.exe /c echo { >> ext_ip.js
cmd.exe /c echo if(request.readyState==4) >> ext_ip.js
cmd.exe /c echo { >> ext_ip.js
cmd.exe /c echo WScript.Echo(request.responseText); >> ext_ip.js 
cmd.exe /c echo notyetready = 0; >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js
cmd.exe /c echo. >> ext_ip.js
cmd.exe /c echo request.open( "GET", "http://www.komar.org/cgi-bin/ip_to_country.pl", true ); >> ext_ip.js 
cmd.exe /c echo request.send(null); >> ext_ip.js 
cmd.exe /c echo. >> ext_ip.js
cmd.exe /c echo while( notyetready ) >> ext_ip.js 
cmd.exe /c echo { >> ext_ip.js 
cmd.exe /c echo WScript.Sleep( 100 ); >> ext_ip.js 
cmd.exe /c echo } >> ext_ip.js 

cmd.exe /c cscript ext_ip.js > results.html
cmd.exe /c findstr /c:"Your IP Address" results.html
cmd.exe /c findstr /c:"Your Hostname" results.html
cmd.exe /c findstr /c:"Your Country Region" results.html

cmd.exe /c findstr /c:"Your IP Address" results.html >> %VAR%-hostinfo.txt
cmd.exe /c findstr /c:"Your Hostname" results.html >> %VAR%-hostinfo.txt
cmd.exe /c findstr /c:"Your Country Region" results.html >> %VAR%-hostinfo.txt



cmd.exe /c del ext_ip.js results.html

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW CHECKING NETWORK CONNECTION INFO      #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

cmd.exe /c netstat -bano > %VAR%-netstat.txt
cmd.exe /c type *-netstat.txt
cmd.exe /c echo.



cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW CHECKING NETWORK ROUTING INFO         #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 


cmd.exe /c route print > %VAR%-route.txt
cmd.exe /c type *-route.txt
cmd.exe /c echo.



cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            NOW CHECKING ARP INFO               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c arp -a > %VAR%-arp.txt
cmd.exe /c type *-arp.txt



cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY NETWORK SHARES                #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net share > %VAR%-shares.txt
cmd.exe /c type *-shares.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY LOCAL USER ACCOUNTS           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net user > %VAR%-users.txt
cmd.exe /c type *-users.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY LOCAL GROUPS                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


cmd.exe /c net localgroup > %VAR%-group.txt
cmd.exe /c type *-group.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #   NOW DISPLAY USERS BELONGING TO ADMIN GROUP   #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


cmd.exe /c net localgroup administrators > %VAR%-localadmins.txt
cmd.exe /c type *-localadmins.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY COMPUTERS IN MY WORKGROUP     #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


cmd.exe /c net view > %VAR%-netview.txt
cmd.exe /c type *-netview.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      NOW DISPLAY DOMAIN INFO                   #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c net view /domain > %VAR%-netdom.txt
cmd.exe /c type *-netdom.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #             Checking Eventlogs                 #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 


powershell get-eventlog system -newest 100 ^| format-table -auto -wrap ^| tee-object -file %VAR%-evtlog-system.txt
 
powershell get-eventlog application -newest 100 ^| format-table -auto -wrap ^| tee-object -file %VAR%-evtlog-app.txt
 
powershell get-eventlog security -newest 100 ^| format-table -auto -wrap ^| tee-object -file %VAR%-evtlog-sec.txt
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #                DRIVE INFORMATION               #
cmd.exe /c echo ##################################################
cmd.exe /c echo. 

powershell get-psdrive ^| tee-object -file %VAR%-psdrive.txt
 

cmd.exe /c fsutil fsinfo drives > %VAR%-fsinfo.txt
cmd.exe /c type *-fsinfo.txt
cmd.exe /c echo.



echo Free Disk Space on C:
cmd.exe /c fsutil volume diskfree c: > %VAR%-fsinfoc.txt
cmd.exe /c vol c: >> %VAR%-fsinfoc.txt
cmd.exe /c fsutil fsinfo drivetype c: >> %VAR%-fsinfoc.txt
cmd.exe /c type *-fsinfoc.txt
cmd.exe /c echo.

 

echo Free Disk Space on D:
cmd.exe /c fsutil volume diskfree d: > %VAR%-fsinfod.txt
cmd.exe /c vol d: >> %VAR%-fsinfod.txt
cmd.exe /c fsutil fsinfo drivetype d: >> %VAR%-fsinfod.txt
cmd.exe /c type *-fsinfod.txt
cmd.exe /c echo.

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #               SYSTEM INFORMATION               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0" > %VAR%-reg-sysinfo.txt
cmd.exe /c type *-reg-sysinfo.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING SOFTWARE KEY               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKLM\Software" > %VAR%-reg-software.txt
cmd.exe /c type *-reg-software.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #       VALUE IN LOCAL MACHINE RUN KEY           #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" > %VAR%-reg-run.txt
cmd.exe /c type *-reg-run.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN LOCAL MACHINE RUNONCE KEY        #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" %VAR%-reg-runonce.txt
cmd.exe /c type *-reg-runonce.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN CURRENT USER RUN KEY             #
cmd.exe /c echo ##################################################
cmd.exe /c echo.



reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" > %VAR%-reg-curun.txt
cmd.exe /c type *-reg-curun.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #      VALUE IN CURRENT USER RUNONCE KEY         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" > %VAR%-reg-curunonce.txt
cmd.exe /c type *-reg-curunonce.txt
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #           NETWORKS IN NETWORK LIST PROFILES    #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s > %VAR%-reg-netprofiles.txt
cmd.exe /c type *-reg-netprofiles.txt


cmd.exe /c echo.
cmd.exe /c echo ############################################################
cmd.exe /c echo #  LISTING THE DEFAULT GATEWAY MAC FOR NET PROFILES        #
cmd.exe /c echo ############################################################
cmd.exe /c echo.


reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged" /s > %VAR%-reg-netsignatures.txt
cmd.exe /c type *-reg-netsignatures.txt

cmd.exe /c echo.
cmd.exe /c echo ############################################################
cmd.exe /c echo #     VIEW AVAILABLE WIRELESS NETWORKS IN THE AREA         #
cmd.exe /c echo ############################################################
cmd.exe /c echo.


cmd.exe /c netsh wlan show all > %VAR%-wlan.txt
cmd.exe /c type *-wlan.txt


cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING IE INFORMATION               #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKCU\Software\Microsoft\Internet Explorer"  > %VAR%-ie.txt
cmd.exe /c type *-ie.txt
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING USER'S IE START PAGE         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKCU\Software\Microsoft\Internet Explorer\Main" /v "Start Page" /t REG_SZ > %VAR%-ie-start.txt
cmd.exe /c type *-ie-start.txt

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING USER'S IE TYPED URL's        #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

reg query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" > %VAR%-ie-urls.txt
cmd.exe /c type *-ie-urls.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #          CHECKING FW CONFIGRUATIONS            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c netsh firewall show opmode > %VAR%-fwmode.txt
cmd.exe /c type *-fwmode.txt
 
cmd.exe /c netsh advfirewall show allprofiles > %VAR%-fwadv.txt
cmd.exe /c type *-fwadv.txt
 

cmd.exe /c netsh advfirewall firewall show rule all > %VAR%-fwrules.txt
cmd.exe /c type *-fwrules.txt
 

reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\AuthorizedApplications\" > %VAR%-reg-fw-apps.txt
cmd.exe /c type *-reg-fw-apps.txt
reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging" > %VAR%-reg-fw-dom-log.txt
cmd.exe /c type *-reg-fw-dom-log.txt
reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging" > %VAR%-reg-fw-std-log.txt
cmd.exe /c type *-reg-fw-std-log.txt
reg query "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FireWallRules" > %VAR%-reg-fw-rules.txt
cmd.exe /c type *-reg-fw-rules.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #              PERFORMING CLEANUP                #
cmd.exe /c echo ##################################################
cmd.exe /c echo.
cmd.exe /c del sysinfo.txt

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING SCHEDULED TASKS            #
cmd.exe /c echo ##################################################
cmd.exe /c echo.


cmd.exe /c dir %SYSTEMROOT%\tasks > %VAR%-tasks.txt
cmd.exe /c type *-tasks.txt
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING PREFETCH DIRECTORY         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.
 

cmd.exe /c dir %SYSTEMROOT%\prefetch > %VAR%-prefetch.txt
cmd.exe /c type *-prefetch.txt

 
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING "AT" JOBS                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c schtasks /query /fo csv /v > %VAR%-schtasks.csv
cmd.exe /c type *-schtasks.csv
 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            CHECKING SERVICES                  #
cmd.exe /c echo ##################################################
cmd.exe /c echo.
powershell Get-Service ^| format-table -auto name,status,displayname ^| tee-object -file %VAR%-services.txt

 

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #     LOOK FOR MODIFIED FILES IN LAST HOUR	 #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

powershell Get-ChildItem -Force -EA 0 c:\ -recurse ^| ?{$_.LastWriteTime -gt (Get-Date).AddMinutes(-60) } ^|select-object directory, name, lastwritetime, length ^| Export-Csv %VAR%-hour-c.csv

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            DIR WALK			         #
cmd.exe /c echo ##################################################
cmd.exe /c echo.

cmd.exe /c choice /C:YN /N /T 30 /D N /M "Do you want a full Dir-Walk of the C: drive? (Could be hours depending on drive)[Y/N]"
IF ERRORLEVEL ==2 Goto HashQuestion
IF ERRORLEVEL ==1 Goto FullDirWalk


:FullDirWalk
powershell Get-ChildItem c:\ -recurse ^| select-object directory, name, lastwritetime, length ^| Export-Csv %VAR%-dirwalk-c.csv

goto HashQuestion

:HashQuestion
cmd.exe /c choice /C:YN /N /T 30 /D N /M HashDir="Do you want a full Dir-Walk and hash of the C: drive? (Could be hours/days depending on drive)[y/n]"
IF ERRORLEVEL ==2 Goto Zip
IF ERRORLEVEL ==1 Goto HashDrive

:HashDrive
powershell Get-ChildItem c:\ -recurse ^| Get-FileHash -algorithm sha1 ^| select-object hash, path ^| Export-CSV %VAR%-dirwalk-c-hashed.csv

:Zip
cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            ZIP Results		         #
cmd.exe /c echo ##################################################
powershell Compress-Archive -Path %computername%-* -DestinationPath %computername%-collection-%VAR%
 
cmd.exe /c del /q %computername%-*.txt
cmd.exe /c del /q %computername%-*.csv

cmd.exe /c echo.
cmd.exe /c echo ##################################################
cmd.exe /c echo #            SCRIPT COMPLETE                     #
cmd.exe /c echo ##################################################
cmd.exe /c echo.




goto exit

:exit
echo Done

:warnthenexit
echo Script exited with errors.

