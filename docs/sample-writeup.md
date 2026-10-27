---
title: "Soul Lab"
room: "Soul Lab"
target: "172.29.99.10"
date: 2026-10-27
tags:
  - writeup
  - ftp
  - web
  - rpc
  - smb
  - nfs
status: in-progress
---

# Soul Lab

> [!info] Target
> `172.29.99.10` · recon by soul-toolkit v0.3.0 on 2026-10-27

## Recon

### Open ports

| Port | Service | Version |
|---|---|---|
| 21/tcp | ftp | vsftpd 2.0.8 or later |
| 80/tcp | http | nginx 1.24.0 (Ubuntu) |
| 111/tcp | rpcbind | 2-4 (RPC #100000) |
| 139/tcp | netbios-ssn | Samba smbd 4.6.2 |
| 445/tcp | netbios-ssn | Samba smbd 4.6.2 |
| 875/tcp | rquotad | 1-2 (RPC #100011) |
| 2049/tcp | nfs | 3-4 (RPC #100003) |
| 8080/tcp | http | nginx 1.24.0 (Ubuntu) |
| 20048/tcp | mountd | 1-3 (RPC #100005) |
| 33763/tcp | nlockmgr | 4 (RPC #100021) |
| 111/udp | rpcbind | 2-4 (RPC #100000) |
| 2049/udp | nfs | 3-4 (RPC #100003) |

### Key findings

- 🔴 **Anonymous FTP login allowed** (21/tcp) - 2 entries in the FTP root
- 🔴 **NFS exports anyone can mount** (2049/tcp) - /srv/nfs
- 🔴 **Exposed .git repository** (8080/tcp) - http://172.29.99.10:8080/.git/HEAD is readable - the source code can likely be reconstructed (e.g. with git-dumper).
- 🟠 **Redirects to virtual host 'lab.thm'** (80/tcp) - GET / -> 302 http://lab.thm/
- 🟠 **Virtual hosts found: dev.lab.thm** (80/tcp) - Add to /etc/hosts: `172.29.99.10 lab.thm dev.lab.thm`
- 🟠 **Null session can list SMB shares** (445/tcp) - public, IPC$ - readable without a password: public
- 🟠 **Interesting paths worth checking** (8080/tcp) - /login.html, /.git/config, /.git/index, /.git/HEAD, /admin/index.html, /backup/index.html, /.git, /admin, /backup, /.git/logs/

### Leads to try

- [ ] **Mount the NFS export /srv/nfs (read-only)** (2049/tcp) - `sudo mkdir -p /mnt/nfs-srv-nfs && sudo mount -t nfs -o ro,nolock 172.29.99.10:/srv/nfs /mnt/nfs-srv-nfs`
- [ ] **Dump the exposed .git repository** (8080/tcp) - `git-dumper http://172.29.99.10:8080/.git/ ./8080-git`
- [ ] **Download everything from anonymous FTP** (21/tcp) - `wget -m ftp://anonymous:anonymous@172.29.99.10/`
- [ ] **Read the 'public' share with a null session** (445/tcp) - `smbclient //172.29.99.10/public -N`
- [ ] **Add the new vhost(s) to /etc/hosts and enumerate them: dev.lab.thm** (80/tcp) - `echo '172.29.99.10 lab.thm dev.lab.thm' | sudo tee -a /etc/hosts`

> [!note]- Commands run during recon
> `nmap -sS -T4 --open -oX - -Pn -p- --min-rate 1000 172.29.99.10`  
> `nmap -sS -T4 --open -oX - -Pn -sV -sC -p 21,80,111,139,445,875,2049,8080,20048,33763 172.29.99.10`  
> `nmap -sU -T4 --open -oX - -Pn --top-ports 100 --min-rate 1000 172.29.99.10`  
> `nmap -sU -T4 --open -oX - -Pn -sV -sC -p 111,2049 172.29.99.10`  
> `gobuster dir -u http://172.29.99.10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q --no-progress --no-error --no-color --timeout 8s -o results/172.29.99.10/gobuster-80.txt`  
> `gobuster dir -u http://172.29.99.10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q --no-progress --no-error --no-color --timeout 8s -o results/172.29.99.10/gobuster-80.txt --exclude-length 154`  
> `ffuf -u http://172.29.99.10/ -H 'Host: FUZZ.lab.thm' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30 -timeout 8 -maxtime 600 -of json -o results/172.29.99.10/vhosts-80.json -s -noninteractive -fs 154`  
> `smbclient -L //172.29.99.10 -N -g -p 445`  
> `smbclient //172.29.99.10/public -N -p 445 -c ls`  
> `showmount -e 172.29.99.10`  
> `gobuster dir -u http://172.29.99.10:8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q --no-progress --no-error --no-color --timeout 8s -o results/172.29.99.10/gobuster-8080.txt -x html,txt`  
> `gobuster dir -u http://172.29.99.10:8080/admin -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q --no-progress --no-error --no-color --timeout 8s -o results/172.29.99.10/gobuster-8080-admin.txt -x html,txt`  
> `gobuster dir -u http://172.29.99.10:8080/backup -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30 -q --no-progress --no-error --no-color --timeout 8s -o results/172.29.99.10/gobuster-8080-backup.txt -x html,txt`  

## Foothold


## Privilege Escalation


## Flags

| Flag | Value |
|---|---|
| user.txt | |
| root.txt | |

## Lessons learned
