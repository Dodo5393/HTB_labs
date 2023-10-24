# Pentest raport for Vaccine box

### CVSS Base Score: 9.8 (Critical)

### CWE-521: Weak Password Requirements

### CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### CWE-285: Improper Authorization 

### CWE-732: Incorrect Permission Assignment for Critical Resource

Description: In this penetration test report, we uncover critical vulnerabilities  within the Vaccine machine's security infrastructure. Despite data  encryption, we were able to easily crack weak passwords to access  sensitive information, which we subsequently encrypted. By exploiting  SQL injection, we established a shell on the victim machine and  identified misconfigured permissions, ultimately gaining root  privileges.

###### POC :

Begin the penetration test by conducting initial scans on the target system.

```bas

┌─[parrot@parrot]─[~]
└──╼ $nmap -sC -sV 10.129.59.35
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-23 18:25 BST
Nmap scan report for 10.129.59.35
Host is up (0.037s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.59
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0ee58077534b00b9165b259569527a4 (RSA)
|   256 ac6e81188922d7a7417d814f1bb8b251 (ECDSA)
|_  256 425bc321dfefa20bc95e03421d69d028 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds
```

We can see an open SSH port, but we don't have the login credentials.  Next, we notice an open HTTP port, and we intend to visit the site  hosted on that port.



![](/home/dodo/Documents/HTB/HTB_lab/HTB_labs/.Vaccine_img/login.png)



